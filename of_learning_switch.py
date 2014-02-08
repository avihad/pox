"""
OpenFlow Exercise - Sample File
This code is based on the official OpenFlow tutorial code.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Hold Port<->Mac hash table.
        self.mac_port_mapping = {}

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch

        self.act_like_switch(packet, packet_in)

    def send_packet (self, buffer_id, raw_data, out_port, in_port):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that. Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
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
        self.connection.send(msg)

    def resend_packet(self, packet_in, out_port):
        """
        @summary: Resend a packet, this time with a new outgoing port on switch
        @param packet_in: holds information about the incoming packet
        @param out_port: an int representing the outgoing port on switch
        """
        msg = of.ofp_packet_out()
        msg.in_port = of.OFPP_NONE
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.buffer_id = packet_in.buffer_id
        if (out_port != of.OFPP_ALL):
            log.debug("Sending packet through port %i on the switch" % out_port)
        self.connection.send(msg)

    def install_rule(self, in_port, packet):
        """
        @summary: Once a port of a device is learned, a rule is created
        @param in_port: an int that represents the incoming port on switch
        @param packet: a local copy of the packet that initiated this rule install
        """
        msg = of.ofp_flow_mod()
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.actions.append(of.ofp_action_output(port=in_port))
        log.debug("Creating a new flow, MAC %s is connected to PORT %i on the switch" % (str(packet.src), in_port))
        self.connection.send(msg)

    def act_like_switch (self, packet, packet_in):
        """
        @summary: Implement switch-like behavior, learn MAC addresses of peer devices.
        @param packet:  packet.src, packet.dst
        @param packet_in: packet_in.port, packet_in.buffer_id, packet_in.data
        """
        src_mac = str(packet.src)
        dst_mac = str(packet.dst)
        in_port = packet_in.in_port
        self.mac_port_mapping[src_mac] = in_port
        if (dst_mac in self.mac_port_mapping):
            out_port = self.mac_port_mapping[dst_mac]
            self.install_rule(in_port, packet)
            self.resend_packet(packet_in, out_port)
        else:
            log.debug("Flooding packet: %s.%i -> %s.%i" % (src_mac, in_port, dst_mac, of.OFPP_ALL))
            self.resend_packet(packet_in, of.OFPP_ALL)

def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
