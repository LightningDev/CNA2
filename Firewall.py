__author__ = 'nhat'

# These next two imports are common POX convention
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

# This table maps (switch,MAC-addr) pairs to the port on 'switch' at
# which we last saw a packet *from* 'MAC-addr'.
# (In this case, we use a Connection object for the switch.)
table = {}

# This table contains the firewall rules:
# firewall[(switch, dl_type, nw_proto, port, src_port)] = TRUE/FALSE
#
# Our firewall only supports inbound rule enforcement per port only.
# By default, this is empty.
# Sample dl_type(s): IP (0x800)
#   Sample nw_proto(s): ICMP (1), TCP (6), UDP (17)
#
firewall = {}

# function that allows adding firewall rules into the firewall table
def AddRule(event, dl_type=0x800, nw_proto=1, port=0, src_port=of.OFPP_ALL):
    firewall[(event.connection, dl_type, nw_proto, port, src_port)] = True
    log.debug("Adding firewall rule to %s: %s %s %s %s" %
              dpidToStr(event.connection.dpid), dl_type, nw_proto, port, src_port)


# function that allows deleting firewall rules from the firewall table
def DeleteRule(event, dl_type=0x800, nw_proto=1, port=0, src_port=of.OFPP_ALL):
    try:
        del firewall[(event.connection, dl_type, nw_proto, port, src_port)]
        log.debug("Deleting firewall rule in %s: %s %s %s %s" %
                  dpidToStr(event.connection.dpid), dl_type, nw_proto, port, src_port)
    except KeyError:
        log.error("Cannot find in %s: %s %s %s %s" %
                  dpidToStr(event.connection.dpid), dl_type, nw_proto, port, src_port)


# function to display firewall rules
def ShowRules():
    for key in firewall:
        log.info("Rule %s defined" % key)


# function to handle all housekeeping items when firewall starts
def _handle_StartFirewall(event):
    ShowRules()
    log.info("Firewall Tutorial is running.")


# function to handle all PacketIns from switch/router
def _handle_PacketIn(event):
    packet = event.parsed

    # only process Ethernet packets
    if packet.type != ethernet.IP_TYPE:
        name1 = pkt.ETHERNET.ethernet.getNameForType(packet.type)
        log.debug(name1)
        return

    # check if packet is compliant to rules before proceeding
    if (firewall[(event.connection, packet.dl_type, packet.nw_proto, packet.tp_src, event.port)] == True):
        log.debug("Rule (%s %s %s %s) FOUND in %s" %
                  dpidToStr(event.connection.dpid), packet.dl_type, packet.nw_proto, packet.tp_src, event.port)
    else:
        log.debug("Rule (%s %s %s %s) NOT FOUND in %s" %
                  dpidToStr(event.connection.dpid), packet.dl_type, packet.nw_proto, packet.tp_src, event.port)
        return

    # Learn the source and fill up routing table
    table[(event.connection, packet.src)] = event.port
    dst_port = table.get((event.connection, packet.dst))

    if dst_port is None:
        # We don't know where the destination is yet. So, we'll just
        # send the packet out all ports (except the one it came in on!)
        msg = of.ofp_packet_out(resend=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        msg.send(event.connection)

        log.debug("Broadcasting %s.%i -> %s.%i" %
                  (packet.src, event.ofp.in_port, packet.dst, of.OFPP_ALL))
    else:
        # Since we know the switch ports for both the source and dest
        # MACs, we can install rules for both directions.
        msg = of.ofp_flow_mod()
        msg.match.dl_type = packet.dl_type
        msg.match.nw_proto = packet.nw_proto
        if (packet.nw_proto != 1):
            msg.match.tp_src = packet.tp_src
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=event.port))
        msg.send(event.connection)

        # This is the packet that just came in -- we want to
        # install the rule and also resend the packet.
        msg = of.ofp_flow_mod()
        msg.match.dl_type = packet.dl_type
        msg.match.nw_proto = packet.nw_proto
        if (packet.nw_proto != 1):
            msg.match.tp_src = packet.tp_src
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=dst_port))
        msg.send(event.connection, resend=event.ofp)

        log.debug("Installing %s.%i -> %s.%i AND %s.%i -> %s.%i" %
                  (packet.dst, dst_port, packet.src, event.ofp.in_port,
                   packet.src, event.ofp.in_port, packet.dst, dst_port))


# main function to start module
def launch():
    core.openflow.addListenerByName("AddRule", AddRule)
    core.openflow.addListenerByName("ConnectionUp", _handle_StartFirewall)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)