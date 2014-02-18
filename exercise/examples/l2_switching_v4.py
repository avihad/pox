##################################
#author -durga
#controller - pox
# L2 controller inserts the flow table entries based on switching rules
# the following code emulates basic source-mac address learning , forwarding
# and filtering mechanisms found on switches. algorithm as below:
# 1.switch forwards an unknown dest packet to the controller
#   > controller to check if (src-mac-add ,src-port-id) pair as in the recieved         packet exists in its addr table. 
#        >a. if no entry , then make an entry
#        >b. if an entry is made, dont change
#   > controller to check for (des-mac-add,dest-port-id) pair in its addr table
#       >a. if an entry is made, send relevant flow mod message to switch with i             formation of outgoing port.
#       >b. if no entry is made, send a flow mod message to switch to broadcast              the packet for that destnation mac addr 
#       >c. if destination port addr is same as source port addr drop the packet#   > send the ofmessage to the out.
##################################
# generic info
# all mentioned events ex:ConnectionUp and PacketIn can be found in pox/openflow/__init__.py
# all events have min of 3 attributes 1. connection 2.ofp (of packet which triggerd the event) 3.dpid
#though there is no req for controller to maintain mac addr table, since the ft on switch expires its always a good idea to have a ref on controller -- macaddrtable{}
###################################

from pox.lib import *
from  pox.core import core  # to import core module to register and hook the module
#from  pox.lib import packet as pkt #to import modules from packet
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *


log = core.getLogger()

class L2_switch (EventMixin):
        print "in L2switch class"
        def __init__(self):
        # as soon as the module is hooked initialise..
                self.macaddrtable = {}
                self.listenTo(core.openflow)#listening to the events from core.openflow


        def _handle_ConnectionUp (self,event):
         # event handler for 'connectionup' events
                print"connected to switch" # log a comment as soon as a connection is established

                def _handle_PacketIn (self,event):
         # event handler for incoming packets.check pox/openflow/__init__.py for infor on PacketIn(Event) class
         # ofp represents the real openflow packet which triggered the event and is an event attribute.

                parsedpkt = event.parsed
                print type(parsedpkt)
                inport = event.ofp.in_port
                data = event.ofp.data
                ethpkt = parsedpkt.find('ethernet')
                print type(ethpkt)
                dstmacaddr = ethpkt.dst
                srcmacaddr = ethpkt.src

        #updating srcmactable
                self.updateMap(inport,srcmacaddr)
        # processing the packet
                self.processPacket(dstmacaddr,inport,event,parsedpkt)

        def floodPacket(self,event):
                message = of.ofp_packet_out()
                message.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                message.data = event.data
                message.in_port = event.port
                return message

        def dropPacket(self,event):
                #no action implies a drop
                message = of.ofp_packet_out()
                #message.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
                message.data = event.data
                message.in_port = event.port
                return message

        def updateMap(self,srcportin,srcmacaddr): # to update the mac-addr, port table
                self.macaddrtable[srcmacaddr] = srcportin

        def processPacket(self,destmacaddr,srcport,event,packet):# frame flow entries to forward the packets based on entries made in macaddrtable

                if destmacaddr.is_multicast: # if mulicast packet, then flood
                        msg = self.floodPacket(event)

                elif destmacaddr in self.macaddrtable.keys():
                        msg = of.ofp_flow_mod()
                        log.debug ("%s"%msg)
                        destport = self.macaddrtable[destmacaddr] # if dest mac addr in macaddr table, update the dest id 
                        if destport != srcport: # if destport is not same as srcport, set the port id in action ad dest port
                                msg.match = of.ofp_match.from_packet(packet,event.port)
                                log.debug ("%s" %msg)
                                msg.actions.append(of.ofp_action_output(port=destport))
                                log.debug ("%s" %msg)
                        elif destport == srcport: #elif destport is same as srcport drop the packet
                                msg = self.dropPacket(event)

                elif destmacaddr not in self.macaddrtable.keys(): # if the destmac aaadr has no entry in macaddr table,bc the packet.
                        msg = self.floodPacket(event)
                self.sendFlowMod(msg,event)

        def sendFlowMod(self,msg,event):
                event.connection.send(msg)
def launch():
        print "in launch.."
        core.registerNew(L2_switch) #registering the component to the core
