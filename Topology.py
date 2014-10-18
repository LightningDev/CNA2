#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNet():

    #OpenDayLight controller
    ODL_CONTROLLER_IP='10.0.0.4'

    #Floodlight controller
    FL_CONTROLLER_IP='10.0.0.5'

    net = Mininet(  controller=Controller )

    # Create nodes
    h1 = net.addHost( 'h1', mac='01:00:00:00:01:00', ip='192.168.0.1/24' )
    h2 = net.addHost( 'h2', mac='01:00:00:00:02:00', ip='192.168.0.2/24' )
    h3 = net.addHost( 'h3', mac='01:00:00:00:03:00', ip='192.168.0.3/24' )
    h4 = net.addHost( 'h4', mac='01:00:00:00:04:00', ip='192.168.0.4/24' )

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )
    s2 = net.addSwitch( 's2', listenPort=6634, mac='00:00:00:00:00:02' )

    print "*** Creating links"
    net.addLink(h1, s1, )
    net.addLink(h2, s1, )
    net.addLink(h3, s2, )
    net.addLink(h4, s2, )
    net.addLink(s1, s2, )

    # Add Controllers
    #odl_ctrl = net.addController( 'c0', controller=RemoteController, ip=ODL_CONTROLLER_IP, port=6633)

    #fl_ctrl = net.addController( 'c1', controller=RemoteController, ip=FL_CONTROLLER_IP, port=6633)

    net.addController('c0')

    #net.build()

    # Connect each switch to a different controller
    #s1.start( [odl_ctrl] )
    # s2.start( [odl_ctrl])
    #s2.start( [fl_ctrl] )

    net.start()

    s1.cmdPrint('ovs-vsctl show')

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()