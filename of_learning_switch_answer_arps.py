"""
OpenFlow Exercise - Sample File
This code is based on the official OpenFlow tutorial code.
"""

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet


# Get the log object
log = core.getLogger()


class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        """
        Constructor
        """
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Hold Port<->Mac hash table.
        self.mac_port_mapping = {}

        # Hold IP<->MAC hash table
        self.ip_mac_mapping = {}

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp

        # Handle a packet of type ARP
        if packet.type == packet.ARP_TYPE:
            (packet_in, packet) = self.handle_arp(event, packet, packet_in)

        self.act_like_switch(packet, packet_in)

    def handle_arp(self, event, packet, packet_in):
        """
        Constructs an appropriate ARP Reply upon an incoming ARP Request
        """
        arp_request = packet.payload

        if arp_request.opcode == arp.REQUEST:
            if arp_request.protosrc not in self.ip_mac_mapping:
                self.ip_mac_mapping[arp_request.protosrc] = arp_request.hwsrc
                log.debug("Got ARP Request message, adding ARP table entry: (IP: %s MAC: %s)" % (str(arp_request.protosrc),
                                                                                                 str(arp_request.hwsrc)))

            if arp_request.protodst in self.ip_mac_mapping:
                arp_reply = self.construct_arp_reply(arp_request)
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = arp_request.hwsrc
                ether.src = self.ip_mac_mapping[arp_request.protodst]
                ether.payload = arp_reply

                packet_in.data = ether
                packet_in.in_port = event.port
                log.debug("Proxy ARP constructing an ARP Reply (SRC(%s:%s) --> DST(%s:%s))" % (arp_request.hwsrc,
                                                                                               arp_request.protosrc,
                                                                                               arp_reply.hwsrc,
                                                                                               arp_reply.protosrc))
        elif arp_request.opcode == arp.REPLY:
            self.ip_mac_mapping[arp_request.protosrc] = arp_request.hwsrc
            log.debug("Got ARP Reply message, adding ARP table entry: (IP: %s MAC: %s)" % (str(arp_request.protosrc),
                                                                                             str(arp_request.hwsrc)))

        return packet_in, packet

    def construct_arp_reply(self, arp_request):
        """
        Create an ARP Reply message
        """
        arp_reply = arp()
        arp_reply.hwsrc = self.ip_mac_mapping[arp_request.protodst]
        arp_reply.hwdst = arp_request.hwsrc
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = arp_request.protodst
        arp_reply.protodst = arp_request.protosrc
        arp_reply.hwtype = arp_request.hwtype
        arp_reply.prototype = arp_request.prototype
        arp_reply.hwlen = 6
        arp_reply.protolen = 4
        return arp_reply

    def send_packet(self, buffer_id, raw_data, out_port, in_port):
        """
        Sends a packet out of the specified switch port.
        """
        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        log.debug("Sending packet")
        self.connection.send(msg)

    def resend_packet(self, packet_in, out_port):
        """
        @summary: Resend a packet, this time with a new outgoing port on switch
        @param packet_in: holds information about the incoming packet
        @param out_port: an int representing the outgoing port on switch
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in.data
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        if out_port != of.OFPP_FLOOD:
            log.debug("Resending packet through port %i on the switch" % out_port)
        self.connection.send(msg)

    def install_rule(self, out_port, packet_in, packet):
        """
        @summary: Once a port of a device is learned, a rule is created
        @param packet: a local copy of the packet that initiated this rule install
        """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.buffer_id = packet_in.buffer_id
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        log.debug("Installing a flow entry, MAC: %s is connected to PORT %i" % (str(packet.dst), out_port))
        self.connection.send(msg)

    def act_like_switch (self, packet, packet_in):
        """
        @summary: Implement switch-like behavior, learn MAC addresses of peer devices.
        @param packet:  packet.src, packet.dst
        @param packet_in: packet_in.in_port, packet_in.buffer_id, packet_in.data
        """
        src_mac = str(packet.src)
        dst_mac = str(packet.dst)
        in_port = packet_in.in_port

        # Handle the mac to port mapping add/update
        if src_mac not in self.mac_port_mapping:
            log.debug("Adding switch table entry: (MAC: %s is at PORT: %i)" % (src_mac, in_port))
        self.mac_port_mapping[src_mac] = in_port

        if dst_mac in self.mac_port_mapping:
            log.debug("MAC: %s found in table --> PORT %s" % (dst_mac, self.mac_port_mapping[dst_mac]))
            out_port = self.mac_port_mapping[dst_mac]
            self.install_rule(out_port, packet_in, packet)
        else:
            log.debug("Flooding packet: %s.%i --> %s.%i" % (src_mac, in_port, dst_mac, of.OFPP_FLOOD))
            self.resend_packet(packet_in, of.OFPP_FLOOD)


def launch():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
