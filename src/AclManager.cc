#include "AclManager.hpp"

#include "lib/qt_executor.hpp"
#include "lib/switch_and_port.hpp"

#include <runos/core/logging.hpp>
#include <oxm/openflow_basic.hh>
#include <boost/endian/arithmetic.hpp>

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

/* Constructor with no actions
 */
AclManager::AclManager() {}

/* init method is called, when controller launches application
 * Its first parameter "Loader" allows to get pointers to other
 * RuNOS applications (if we need in some services from core
 * or user applications). Its second parameter "Config" is JSON
 * config "runos-settings.json".
 */
void AclManager::init(Loader *loader, const Config &config) {

    LOG(INFO) << "AclManager: initialization is starting";

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

    controller->register_handler([=](of13::PacketIn& pi, OFConnectionPtr conn) mutable -> bool
    {
        LOG(WARNING) << "loooooooooooooooooool";
        /* Check that connection is still valid (not null).
         */
        if (not conn) {
            return false;
        }
        LOG(WARNING) << "keeeeeeeeeeeeeeeeeeeeeeek";
        /* Check that PacketIn was received with the rule,
         * that has alias of our application.
         */
        uint64_t pi_cookie = pi.cookie();
        if (pi_cookie != COOKIE) {
            return false;
        }
        LOG(INFO) << "AclManager: processing is starting";

        LOG(INFO) << "AclManager: processing finished";

        return false;
    }, -100);

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
    auto conf = config_cd(config, "acl-manager");

    LOG(INFO) << "AclManager: initialization finished";
}

/* Method that is called on all new SDN switches
 */
void AclManager::onSwitchUp(SwitchPtr ptr) {
    default_rules(ptr);
    LOG(INFO) << "AclManager: default rules are installed";
}

}
