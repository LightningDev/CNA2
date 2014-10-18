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
        self.set_rule(0x800, 1, 0, 1)
        self.set_rule(0x800, 1, 0, 2)
        log.debug("Enabling Firewall module")

    def set_rule(self, dl_type, nw_proto, port, src_port):
        self.firewall[(dl_type,nw_proto,port,src_port)]=True
        log.debug("Added firewall rule")

    # function to handle all PacketIns from switch/router
    def _handle_PacketIn(self, event):
        packet = event.parsed

        # if packet.find('ipv6'):
        #     log.debug ("IPV6 cannot go through, rejected")
        #     return

        # only process Ethernet packets
        # if packet.type != ethernet.IP_TYPE:
        #     name1 = pkt.ETHERNET.ethernet.getNameForType(packet.type)
        #     log.debug(name1)
        #     return

        # check if packet is compliant to rules before proceeding
        if not packet.parsed:
            log.warning ("Ignore incomplete packet")
            return

        packet_in = event.ofp


        if packet.type == ethernet.ARP_TYPE:
             log.debug("ARP Go Through")
        else:
            if packet.type == ethernet.IP_TYPE:
                ip_packet = packet.payload
                packet_protocol = ip_packet.protocol
                protocol_packet = ip_packet.payload
                self.src_port = -1

                # ICMP
                if packet_protocol == 1:
                    self.src_port = 0

                # TCP or UDP
                if packet_protocol == 6 or packet_protocol == 17:
                    self.src_port = protocol_packet.srcport

                log.debug ("Protocol %s" % packet_protocol)
                log.debug ("Protocol Src Port %s" % self.src_port)
                log.debug ("Event port %s" % event.port)
                log.debug ("Source MAC %s " % str(packet.src))
                log.debug ("Event MAC %s " % str(event.connection))
                log.debug ("Destination MAC %s " % str(packet.dst))

                # If it was ICMP, TCP or UDP, check it in firewall rules
                if self.src_port > -1:
                    # If the rule is added in dictionary, check it
                    if (0x800, packet_protocol, self.src_port, event.port) in self.firewall:
                        if self.firewall[0x800, packet_protocol, self.src_port, event.port]:
                            log.debug("Rule is allowed and go through")
                        else:
                            log.debug("Rule is not allowed, rejected")
                    # else continue because it was not be blocked by the rules
                    else:
                        log.debug("Not in restricted rule, so go through")
            # Only IPV4 and ARP type of ethernet are checked, the others are allowed to go through (ie.ipv6,vlan)
            else:
                log.debug("Packet Ethernet Type %s go through" % pkt.ETHERNET.ethernet.getNameForType(packet.type))


        # Implement Switch
        self.table[str(packet.src)] = packet_in.in_port

        if str(packet.dst) in self.table:
            port = self.table[str(packet.dst)]
            log.debug("installing flow for %s.%i -> %s.%i" % (packet.src, packet_in.in_port, packet.dst, port))

            # create new flow with match record set to match dest and src
            msg = of.ofp_flow_mod()
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port = port))
            msg.buffer_id = packet_in.buffer_id
            self.connection.send(msg)
        else:
            # Flood the packet out everything but the input port using
            # ofp_packet_out()to send message to the switch

            msg = of.ofp_packet_out()
            msg.in_port = packet_in.in_port
            if packet_in.buffer_id != -1 and packet_in.buffer_id is not None:
                # We got a buffer ID from switch; use that
                msg.buffer_id = packet_in.buffer_id
            else:
                # No buffer ID from switch -- we got the raw data
                if packet_in.data is None:
                    # No raw data specified -- nothing to send
                    return
                msg.data = packet_in.data

            # Add an action to send to the specified port
            action = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg.actions.append(action)
            self.connection.send(msg)

    def handle_flow_stats (event):
        web_bytes = 0
        web_flows = 0
        for f in event.stats:
            if f.match.tp_dst == 80 or f.match.tp_src == 80:
                web_bytes += f.byte_count
                web_flows += 1

        log.info("Web traffic: %s bytes over %s flows", web_bytes, web_flows)
def launch():
    def start_switch (event):
        log.debug ("Controlling %s" % (event.connection,))
        MyFireWall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.openflow.addListenerByName("FlowStatsReceived", start_switch)



