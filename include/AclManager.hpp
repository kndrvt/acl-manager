/* AclManager.hpp */
#pragma once

#include "Application.hpp"
#include "Loader.hpp"
#include "Controller.hpp"
#include "SwitchManager.hpp"
#include "OFMsgSender.hpp"
#include "OFMessage.hpp"
#include "api/Packet.hpp"

#include <unordered_map>
#include <vector>

using std::unordered_map;
using std::vector;


namespace runos {

    class AclManager : public Application {
    Q_OBJECT
    SIMPLE_APPLICATION(AclManager, "acl-manager")

        int xid = 21;
        unordered_map<uint32_t, vector<uint32_t>> rules;
        void default_rules(SwitchPtr ptr);
        void set_rule(SwitchPtr ptr, uint16_t value, bool flag);
        void send_icmp_error(Packet & pkt, uint64_t dpid);

        OFMessageHandlerPtr handler;
        Controller *controller;
        OFMsgSender *sender;

    public:
        /* init method is called, when controller launches application
         * Its first parameter "Loader" allows to get pointers to other
         * RuNOS applications (if we need in some services from core
         * or user applications). Its second parameter "Config" is JSON
         * config "runos-settings.json".
         */
        void init(Loader *loader, const Config &config) override;

        /* Method that is called on all new SDN switches
         */
        void onSwitchUp(SwitchPtr ptr);

    };

}
