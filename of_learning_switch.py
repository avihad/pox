"""
OpenFlow Exercise - Sample File
This code is based on the official OpenFlow tutorial code.

@author: Avihad Menahem (301001806)
@author: Elad Hayun (066716754)
"""

# Imports
from pox.core import core
import pox.openflow.libopenflow_01 as of

# Get the log object
log = core.getLogger()

class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        """
        @summary: Constructor
        @param connection: A Connection object for that switch
        @return: void
        """
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Hold Port<->Mac hash table.
        self.mac_port_mapping = {}

    def _handle_PacketIn (self, event):
        """
        @summary: Handles packet in messages from the switch.
        @param event: the event invoked
        @return: void
        """

        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch

        self.act_like_switch(packet, packet_in)

    def send_packet (self, buffer_id, raw_data, out_port, in_port):
        """
        @summary: Sends a packet out of the specified switch port
        @param buffer_id: the unique ID of the packet in the switch (may not be present)
        @param raw_data: the raw data of the packet (may not be present)
        @param out_port: the port number on which the packet should be sent on the switch
        @param in_port: the port number on which the packet arrived at the switch
        @return: void
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
        @return: void
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in.data
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        if (out_port != of.OFPP_FLOOD):
            log.debug("Resending packet through port %i on the switch" % out_port)
        self.connection.send(msg)

    def install_rule(self, out_port, packet_in, packet):
        """
        @summary: Once a port of a device is learned, a rule is created
        @param packet: a local copy of the packet that initiated this rule install
        @param out_port: Port where to set the flow entry to
        @return: void
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
        if not (src_mac in self.mac_port_mapping):
            log.debug("Adding switch table entry: (MAC: %s is at PORT: %i)" % (src_mac, in_port))
        self.mac_port_mapping[src_mac] = in_port
        if (dst_mac in self.mac_port_mapping):
            log.debug("MAC: %s found in table --> PORT %s" % (dst_mac, self.mac_port_mapping[dst_mac]))
            out_port = self.mac_port_mapping[dst_mac]
            self.install_rule(out_port, packet_in, packet)
        else:
            log.debug("Flooding packet: %s.%i --> %s.%i" % (src_mac, in_port, dst_mac, of.OFPP_FLOOD))
            self.resend_packet(packet_in, of.OFPP_FLOOD)

def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
