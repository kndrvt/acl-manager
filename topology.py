#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.link import OVSLink
from mininet.log import setLogLevel, info


def main():

    setLogLevel('info')

    info("### Create a network \n")
    net = Mininet(switch=OVSSwitch, controller=RemoteController, link=OVSLink, waitConnected=True, build=False)

    info("### Add a controller \n")
    c0 = net.addController('c0', ip='127.0.0.1', port=6653, protocols="OpenFlow13")

    info("### Adding routers and hosts \n")
    s1 = net.addSwitch('s1', protocols="OpenFlow13")
    s2 = net.addSwitch('s2', protocols="OpenFlow13")
    s3 = net.addSwitch('s3', protocols="OpenFlow13")
    s4 = net.addSwitch('s4', protocols="OpenFlow13")
    s5 = net.addSwitch('s5', protocols="OpenFlow13")

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    h5 = net.addHost('h5', ip='10.0.0.5/24')
    h6 = net.addHost('h6', ip='10.0.0.6/24')
    h7 = net.addHost('h7', ip='10.0.0.7/24')

    info("### Add links \n")
    l1 = net.addLink(h1, s1)
    l2 = net.addLink(h2, s2)
    l3 = net.addLink(h3, s3)
    l4 = net.addLink(h4, s1)
    l5 = net.addLink(h5, s5)
    l6 = net.addLink(h6, s5)
    l6 = net.addLink(h7, s5)

    l7 = net.addLink(s1, s2)
    l8 = net.addLink(s2, s4)
    # l9 = net.addLink(s1, s3)
    l10 = net.addLink(s3, s4)
    l11 = net.addLink(s4, s5)

    info("### Start HTTP servers \n")
    h5.cmd("python -m http.server 80 &")
    h6.cmd("python -m http.server 80 &")
    h7.cmd("python -m http.server 80 &")

    info("### Start network \n")
    net.build()
    net.start()

    info("### Start CLI \n")
    CLI(net)

    info("### Stopping network \n")
    net.stop()


if __name__ == '__main__':
    main()
