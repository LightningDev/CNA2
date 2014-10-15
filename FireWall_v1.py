from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import os
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()


class MyFireWall(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.table = {}
        self.firewall = {}
        self.set_rule(0x800, 1, 0, of.OFPP_ALL)
        log.debug("Enabling Firewall module")

    def set_rule(self, dl_type, nw_proto, port, src_port):
        self.firewall[(dl_type,nw_proto,port,src_port)]=True
        log.debug("Added firewall rule")

    # function to handle all PacketIns from switch/router
    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.find('ipv6'):
            log.debug ("IPV6 cannot go through, rejected")
            return

        # only process Ethernet packets
        # if packet.type != ethernet.IP_TYPE:
        #     name1 = pkt.ETHERNET.ethernet.getNameForType(packet.type)
        #     log.debug(name1)
        #     return

        # check if packet is compliant to rules before proceeding

        if packet.type == ethernet.ARP_TYPE:
            log.debug("ARP Go Through")
        else:
            ip_packet = packet.payload
            self.packet_protocol = ip_packet.protocol
            self.protocol_packet = self.packet_protocol.payload
            if packet.type == ethernet.IP_TYPE:
                if self.firewall[0x800, self.packet_protocol, self.protocol_packet.srcport, event.port]:
                    log.debug("Rule found and go through")
                else:
                    log.debug("Rule not found, rejected")
                    return
            else:
                log.debug("Packet type is not allowed")


        # if self.firewall[packet.dl_type, packet.nw_proto, packet.tp_src, event.port]:
        #     log.debug("Rule (%s %s %s %s) FOUND in %s" %
        #               dpidToStr(event.connection.dpid), packet.dl_type, packet.nw_proto, packet.tp_src, event.port)
        # else:
        #     log.debug("Rule (%s %s %s %s) NOT FOUND in %s" %
        #               dpidToStr(event.connection.dpid), packet.dl_type, packet.nw_proto, packet.tp_src, event.port)
        #     return

        # Implement Switch






        # Learn the source and fill up routing table
        self.table[(event.connection, packet.src)] = event.port
        dst_port = self.table.get((event.connection, packet.dst))

        if dst_port is None:
            # We don't know where the destination is yet. So, we'll just
            # send the packet out all ports (except the one it came in on!)
            msg = of.ofp_packet_out()
            msg.in_port = event.ofp.in_port
            msg.data = event.ofp.data

            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            self.connection.send(msg)

            log.debug("Broadcasting %s.%i -> %s.%i" %
                      (packet.src, event.ofp.in_port, packet.dst, of.OFPP_FLOOD))
        else:
            # Since we know the switch ports for both the source and dest
            # MACs, we can install rules for both directions.
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x800
            # msg.match.nw_proto = self.packet_protocol
            # if self.packet_protocol != 1:
            #     msg.match.tp_src = packet.tp_src
            msg.match.dl_dst = packet.src
            msg.match.dl_src = packet.dst
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)

            # This is the packet that just came in -- we want to
            # install the rule and also resend the packet.
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x800
            # msg.match.nw_proto = self.packet_protocol
            # if self.packet_protocol != 1:
            #     msg.match.tp_src = packet.tp_src
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=dst_port))
            self.connection.send(msg)

            log.debug("Installing %s.%i -> %s.%i AND %s.%i -> %s.%i" %
                      (packet.dst, dst_port, packet.src, event.ofp.in_port,
                       packet.src, event.ofp.in_port, packet.dst, dst_port))

def launch():
    def start_switch (event):
        log.debug ("Controlling %s" % (event.connection,))
        MyFireWall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)



