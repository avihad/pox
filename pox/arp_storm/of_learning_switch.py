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
        # We tell the switch to take the packet with id buffer_if from in_port
        # and send it to out_port
        # If the switch did not specify a buffer_id, it must have specified
        # the raw data of the packet, so in this case we tell it to send
        # the raw data
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
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        log.debug("Sending packet to port %i" % out_port)
        self.connection.send(msg)

    def install_rule(self, src_mac, dst_mac, in_port, out_port, packet_in):
        """
        """
        msg = of.ofp_flow_mod()
        msg.data = packet_in
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.match.dl_src = src_mac
        msg.match.dl_dst = dst_mac
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        log.debug("Instaling flow %s.%i -> %s.%i" % (src_mac, in_port, dst_mac, out_port))
        return msg

    def act_like_hub (self, packet, packet_in):
        """
        Implement hub-like behavior -- send all packets to all ports besides
        the input port.
        """

        # We want to output to all ports -- we do that using the special
        # of.OFPP_FLOOD port as the output port.  (We could have also used
        # of.OFPP_ALL.)

        # Useful information on packet_in:
        # packet_in.buffer_id   - The ID of the buffer (packet data) on the switch
        # packet_in.data        - The raw data as sent by the switch
        # packet_in.in_port     - The port on which the packet arrived at the switch

        # Should call self.send_packet( ... )

        # log.debug('Flooding packet')
        # self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        # self.add_flood_rule_to_flowtable(packet_in.buffer_id, packet_in.data, packet_in.in_port)

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
            msg = self.install_rule(src_mac, dst_mac, in_port, out_port, packet_in)
            log.debug("Sending packet to port %i only" % self.mac_port_mapping[msg.match.dl_dst])
            self.connection.send(msg)
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
