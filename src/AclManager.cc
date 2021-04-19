#include "AclManager.hpp"

#include "lib/qt_executor.hpp"
#include "lib/switch_and_port.hpp"

#include <runos/core/logging.hpp>
#include <oxm/openflow_basic.hh>
#include <boost/endian/arithmetic.hpp>
#include <tins/icmp.h>
#include <tins/ip.h>
#include <tins/ethernetII.h>
#include "PacketParser.hpp"
#include "oxm/openflow_basic.hh"


#include <map>
#include <string>
#include <vector>

using std::map;
using std::string;
using std::vector;

namespace of13 = fluid_msg::of13;

namespace protocols {
    constexpr uint16_t ip = 0x0800;
    constexpr uint8_t tcp = IPPROTO_TCP;
}

namespace runos {

    /* Cookie is used for switch rules alias.
     * Each application should use own unique cookie
     */
    static constexpr uint64_t COOKIE = 0x2021;

    /* Application should register itself with the following call.
     * Without this call no init application method will be called.
     * The second parameter reflects dependencies of your application.
     * They are required to start all applications in proper order.
     * Pay your attention to last empty string (required).
     */
    REGISTER_APPLICATION(AclManager,
{
    "switch-manager", "ofmsg-sender", "controller", ""
}
)


void AclManager::default_rules(SwitchPtr ptr) {
    set_rule(ptr, 0x50, true); // src_port 80
    set_rule(ptr, 0x50, false); // dst_port 80
    set_rule(ptr, 0x1F90, true); // src_port 8080
    set_rule(ptr, 0x1F90, false); // dst_port 8080
}

void AclManager::set_rule(SwitchPtr ptr, uint16_t value, bool flag) {
    of13::FlowMod ofm;
    ofm.command(of13::OFPFC_ADD);
    /* We use only first table with the number 0 */
    ofm.table_id(0);
    /* This xid is needed to process Errors in case
     * if rule was not installed.
     */
    ofm.xid(xid);
    /* We use COOKIE of our application.
     * It will be easier to delete all rules of our
     * application if we simply specify that SDN
     * switch should delete all rules with this cookie.
     */
    ofm.cookie(COOKIE);
    /* Priority is used when packet can be applied to
     * several rules. Then only rule with highest
     * priority is executed.
     */
    ofm.priority(5);
    /* Further we define, what fields and what values
     * our packet in interest should have
     */
    ofm.add_oxm_field(new of13::EthType(protocols::ip)); // IP
    ofm.add_oxm_field(new of13::IPProto(protocols::tcp)); // UDP
    if (flag) {
        ofm.add_oxm_field(new of13::TCPSrc(value));
    } else {
        ofm.add_oxm_field(new of13::TCPDst(value));
    }
    /* Action is transmission to the controller
     */
    of13::ApplyActions actions;
    actions.add_action(new of13::OutputAction(of13::OFPP_CONTROLLER, of13::OFPCML_NO_BUFFER));
    ofm.add_instruction(actions);

    /* Sending of our message
     */
    sender->send(ptr->dpid(), ofm);
}

void AclManager::send_icmp_error(Packet & pkt, uint64_t dpid) {
    auto mac_src = pkt.load(oxm::eth_src());
    auto ip_src = pkt.load(oxm::ipv4_src());
    auto ip_dst = pkt.load(oxm::ipv4_dst());
    auto in_port = pkt.load(oxm::in_port());

    Tins::EthernetII eth = Tins::EthernetII(Tins::HWAddress<6>((uint8_t *) & mac_src)) / 
    Tins::IP(Tins::IPv4Address(htonl(ip_src))) / Tins::ICMP(Tins::ICMP::Flags::DEST_UNREACHABLE);

    of13::PacketOut po;
    auto bytes = eth.serialize();
    po.data(bytes.data(), bytes.size());
    po.add_action(new of13::OutputAction(in_port, 0));
    po.in_port(of13::OFPP_CONTROLLER);
    sender->send(dpid, po);
}

/* init method is called, when controller launches application
 * Its first parameter "Loader" allows to get pointers to other
 * RuNOS applications (if we need in some services from core
 * or user applications). Its second parameter "Config" is JSON
 * config "runos-settings.json".
 */
void AclManager::init(Loader *loader, const Config &config) {

    LOG(INFO) << "Initialization is starting";

    /* Application Controller is required to register
     * our message handler, which is in class implementation
     * Method register_handler takes two parameters:
     * first is pointer to handler and second is priority
     * (in which order the processes from all applications
     *  will be called).
     *
     *  All applications can be accessed with the following call:
     *  ApplicationClass::get(loader)
     */
    controller = Controller::get(loader);

    handler = controller->register_handler(
        [=](of13::PacketIn& pi, OFConnectionPtr conn) mutable -> bool
    {
        LOG(INFO) << "We received PacketIn";
        /* Check that connection is still valid (not null).
         */
        if (not conn) {
            return false;
        }
        /* Check that PacketIn was received with the rule,
         * that has alias of our application.
         */
        uint64_t pi_cookie = pi.cookie();
        if (pi_cookie != COOKIE) {
            return false;
        }
        LOG(INFO) << "Processing is starting";
        PacketParser pp(pi);
        Packet& pkt(pp);

        bool res = false;
        auto ip_src = pkt.load(oxm::ipv4_src());
        auto ip_dst = pkt.load(oxm::ipv4_dst());
        auto dpid = conn->dpid();

        if (rules.find(ip_src) != rules.end()) {
            for (auto & addr: rules[ip_src]) {
                if (ip_dst == addr) {
                    res = true;
                    send_icmp_error(pkt, dpid);
                    break;
                }
            }

        }

        LOG(INFO) << "Processing finished";
        return res;
    }, 10);

    /* Application SwitchManager is required to connect to signal (QT),
     * that announces the new switch in SDN topology.
     */
    SwitchManager *switch_manager = SwitchManager::get(loader);
    QObject::connect(switch_manager, &SwitchManager::switchUp, this, &AclManager::onSwitchUp);

    /* Application OFMsgSender is required for message
     * transmission to the SDN switches.
     */
    sender = OFMsgSender::get(loader);
    /* Read the config file and extract parameters for our application.
     */
    auto restricting_rules = config_cd(config_cd(config, "acl-manager"), "restricting_rules");
    for (auto &rr: restricting_rules) {

        uint32_t src_addr = htonl(Tins::IPv4Address(rr.first));
        rules[src_addr] = vector<uint32_t>();
        vector<Json> dst_addresses = rr.second.array_items();

        for (auto &dst_address: dst_addresses) {
            rules[src_addr].push_back(htonl(Tins::IPv4Address(dst_address.string_value())));
        }
    }

    LOG(INFO) << "Rules:";

    for (auto &rr: rules) {
        LOG(INFO) << rr.first << ": ";
        for (auto &s: rr.second) {
            LOG(INFO) << s << " ";
        }
    }

    LOG(INFO) << "Initialization finished";
}

/* Method that is called on all new SDN switches
 */
void AclManager::onSwitchUp(SwitchPtr ptr) {
    default_rules(ptr);
    LOG(INFO) << "Default rules are installed";
}

}
