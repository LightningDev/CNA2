from pox.core import core
from pox.lib.packet.arp import arp
from pox.lib.util import dpidToStr, dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import os
from pox.lib.packet.ethernet import ethernet
from pox.openflow.of_json import *
import csv

log = core.getLogger()

class MyFireWall(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.routingtable = {}
        log.debug("Enabling Firewall module")
        self.macRules = []
        self.ipRules = []

        with open("mac.csv", 'rb') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.macRules.append((EthAddr(row['mac_0']), EthAddr(row['mac_1'])))
                self.macRules.append((EthAddr(row['mac_1']), EthAddr(row['mac_0'])))
                log.debug("MAC RULE READ")

        with open("ip.csv", 'rb') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.ipRules.append((IPAddr(row['ip_0']), IPAddr(row['ip_1'])))
                self.ipRules.append((IPAddr(row['ip_1']), IPAddr(row['ip_0'])))
                log.debug("IP RULE READ")

    def _handle_ConnectionUp (self, event):
        # for (src, dst) in self.macRules:
        #     match = of.ofp_match()
        #     match.dl_src = src
        #     match.dl_dst = dst
        #     msg = of.ofp_flow_mod()
        #     msg.match = match
        #     msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        #     event.connection.send(msg)

        # for (src, dst) in self.ipRules:
        #     match = of.ofp_match()
        #     match.dl_type = 0x800
        #     match.nw_src = src
        #     match.nw_dst = dst
        #     match.nw_proto = 0x01
        #     msg = of.ofp_flow_mod()
        #     msg.match = match
        #     msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        #     event.connection.send(msg)

        log.debug("Firewall runs on %s", dpidToStr(event.dpid))

    # function to handle all PacketIns from switch/router
    def _handle_PacketIn(self, event):

        packet = event.parsed

        #check if packet is compliant to rules before proceeding
        if not packet.parsed:
            log.warning("Ignore incomplete packet")
            return

        ############################### FIRE-WALL ####################################

        # MAC
        if (packet.src, packet.dst) in self.macRules:
            match = of.ofp_match()
            match.dl_src = packet.src
            match.dl_dst = packet.dst
            msg = of.ofp_flow_mod()
            msg.match = match
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(msg)
            log.debug("MAC RULE ADDED")
            return

        # ARP
        # if packet.type == packet.ARP_TYPE:
        #     if packet.payload.opcode == arp.REQUEST:
        #         src = packet.payload.protosrc
        #         dst = packet.payload.protodst
        #         if (src, dst) in self.ipRules:
        #             match = of.ofp_match()
        #             match.dl_type = 0x0806
        #             match.nw_src = src
        #             match.nw_dst = dst
        #             match.nw_proto = 0x01
        #             msg = of.ofp_flow_mod()
        #             msg.match = match
        #             msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        #             event.connection.send(msg)
        #             log.debug("ARP RULE ADDED")
        #             return

        # Ethernet
        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            protocol = ip_packet.protocol
            ipsrc = ip_packet.srcip
            ipdst = ip_packet.dstip
            if (ipsrc, ipdst) in self.ipRules:
                 # ICMP
                if protocol == 1:
                    match = of.ofp_match()
                    match.dl_type = 0x800
                    match.nw_src = ipsrc
                    match.nw_dst = ipdst
                    match.nw_proto = 1
                    msg = of.ofp_flow_mod()
                    msg.match = match
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
                    event.connection.send(msg)
                    log.debug("ICMP RULE ADDED")
                    return
                # TCP
                elif protocol == 6:
                    match = of.ofp_match()
                    match.dl_type = 0x800
                    match.nw_src = ipsrc
                    match.nw_dst = ipdst
                    match.nw_proto = 6
                    msg = of.ofp_flow_mod()
                    msg.match = match
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
                    event.connection.send(msg)
                    log.debug("TCP RULE ADDED")
                    return
                # UDP
                elif protocol == 17:
                    match = of.ofp_match()
                    match.dl_type = 0x800
                    match.nw_src = ipsrc
                    match.nw_dst = ipdst
                    match.nw_proto = 17
                    msg = of.ofp_flow_mod()
                    msg.match = match
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
                    event.connection.send(msg)
                    log.debug("UDP RULE ADDED")
                    return

        ################################ Switch ######################################

        packet_in = event.ofp

        self.routingtable[str(packet.src)] = packet_in.in_port

        if str(packet.dst) in self.routingtable:
            port = self.routingtable[str(packet.dst)]
            log.debug("Installing flow for %s.%i -> %s.%i" % (packet.src, packet_in.in_port, packet.dst, port))
            # create new flow with match record set to match dest and src
            msg = of.ofp_flow_mod()
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(port=port))
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
            action = of.ofp_action_output(port=of.OFPP_FLOOD)
            msg.actions.append(action)
            self.connection.send(msg)

    def _handle_FlowStatsReceived(self, event):
        stats = flow_stats_to_list(event.stats)
        log.debug("FlowStatsReceived from %s: %s",
                  dpidToStr(event.connection.dpid), stats)

        # Get number of bytes/packets in flows for web traffic only
        web_bytes = 0
        web_flows = 0
        web_packet = 0
        for f in event.stats:
            if f.match.tp_dst == 80 or f.match.tp_src == 80:
                web_bytes += f.byte_count
                web_packet += f.packet_count
                web_flows += 1
        log.info("Web traffic from %s: %s bytes (%s packets) over %s flows",
                 dpidToStr(event.connection.dpid), web_bytes, web_packet, web_flows)


def _timer_func():
    for connection in core.openflow.connections.values():
        connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
        connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    log.debug("Sent %i flow/port stats request(s)", len(core.openflow.connections))


def launch():
    from pox.lib.recoco import Timer

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        MyFireWall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    Timer(10, _timer_func, recurring=True)