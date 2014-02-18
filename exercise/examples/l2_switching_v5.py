##################################

#author -durga
#controller - pox
# L2 controller inserts the flow table entries based on switching rules
# the following code emulates basic source-mac address learning , forwarding
# and filtering mechanisms found on switches. algorithm as below:
# 1.switch forwards any packet with no match to the controller
#   > controller to check if (src-mac-add ,src-port-id) pair be updated in the srcmacaddr table.
#   > if dest is a multicast - flood the packet
#   > controller to check for (des-mac-add,dest-port-id) pair in its addr table
#       >a. if an entry is made, send relevant flow mod message(with a match statement) to switch with information of outgoing port.
#       >b. if no entry is made, the controller insturcts the switch to  broadcast the packet for that destnation mac addr 
#       >c. if destination port addr is same as source port addr drop the packet#   > send the ofmessage to the out.

##################################
# generic info
# all mentioned events ex:ConnectionUp and PacketIn can be found in pox/openflow/__init__.py
# all events have min of 3 attributes 1. connection 2.ofp (of packet which triggerd the event) 3.dpid
#though there is no req for controller to maintain mac addr table, since the ft on switch expires its always a good idea to have a ref on controller -- macaddrtable{}
#in v5 version, trying to accomodate multiple switches.
###################################

from pox.lib import *
from  pox.core import core  # to import core module to register and hook the module
#from  pox.lib import packet as pkt #to import modules from packet
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpid_to_str


log = core.getLogger()

class l2_learning(EventMixin):
        def __init__(self,transparent):
                self.listenTo(core.openflow)
                self.transparent = transparent

        def _handle_ConnectionUp(self,event):#everytime a connection is established, a new switch instance is created
                L2switch(event.connection,self.transparent)

class L2switch(object):
        def __init__(self,connection,transparent):
        # as soon as the module is hooked initialise..
                self.macaddrtable = {}
                self.transparent = transparent
                self.connection = connection
                connection.addListeners(self)


        def _handle_PacketIn (self,event):
         # event handler for incoming packets.check pox/openflow/__init__.py for infor on PacketIn(Event) class. ofp represents the real openflow packet which triggered the event and is an event attribute.
        # processing the packet
        #       log.debug ("%s" %event.ofp)
                self.processPacket(event)

        def floodPacket(self,event):
                message = of.ofp_packet_out()
                message.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                message.data = event.data
                message.in_port = event.port
                return message


        def dropPacket(self,event):
                message = of.ofp_packet_out()
                message.data = event.data
                message.in_port = event.port
                return message

        def updateMap(self,srcportin,srcmacaddr): # to update the mac-addr, port table
                self.macaddrtable[srcmacaddr] = srcportin


        def sendFlowMod(self,msg,event):
                event.connection.send(msg)

        def processPacket(self,event):# frame flow entries to forward the packets based on entries made in macaddrtable
                parsedpkt = event.parsed
        #       log.debug("%i --> %s" ,event.dpid,parsedpkt)
                inport = event.port
        #       log.debug("%s-->%s",inport,data)
                dstmacaddr = parsedpkt.dst
                srcmacaddr = parsedpkt.src
                self.updateMap(inport,srcmacaddr)
                msg = of.ofp_flow_mod()#default setting
                msg.match = of.ofp_match.from_packet(parsedpkt,inport)
                msg.data = event.ofp

                if not self.transparent:
                        if parsedpkt.type == parsedpkt.LLDP_TYPE or dstmacaddr.isBridgeFiltered():
                                msg = self.dropPacket(event)
                                return

                if dstmacaddr.is_multicast: # if mulicast packet, then flood
                        msg = self.floodPacket(event)


                elif dstmacaddr not in self.macaddrtable:#if destmac not in macaddrtable,flood
                        msg = self.floodPacket(event)

                elif dstmacaddr in self.macaddrtable:# if dstmac in macaddrtable
                        dstport = self.macaddrtable[dstmacaddr] #choose port
                        if dstport == event.port: #if same as inport , drop the packet
                                msg = self.dropPacket(event)
                                print "dropping"
                        elif dstport != event.port : #else, insert a flow table entry
                                msg.actions.append(of.ofp_action_output(port = dstport))
                #               log.debug ("%s"%msg)
                
                self.sendFlowMod(msg,event)


def launch():
        print "in launch.."
        core.registerNew(l2_learning,False) #registering the component to the core



