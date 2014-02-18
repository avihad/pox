#author : durga
#program : proxyARP & L3 switch
#intial packets with unknown destinations are sent to controller.controller builds ARPtable subsequently , does proxy arp whereever possible
# if no entry on the controller, the switches will BC ARP packet.
#controller to maintain a db of all connected switches
#a single ARPtable at the controller
#the controller intialises a switch module for each new connection established.

from pox.lib import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet,ETHER_BROADCAST
log = core.getLogger()

global ARPTable
ARPTable = {}

class L3Component(EventMixin):

        def __init__(self):
        #       self.ARPTable = {}
                self.connections = {}
                self.listenTo(core.openflow)

        def _handle_ConnectionUp(self,event):
                #as soon as a connection is established,not neccesary as this entry would anyways expire. refer notes#
                        self.connections[event.dpid] = event.connection #tracking each switch connection
                #       forpkt = of.ofp_flow_mod()
                #       forpkt.match = of.ofp_match() # creating a match entry 
                #       forpkt.match.nw_proto = 1
                #       forpkt.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
                #       event.connection.send(forpkt)
                        l3switching(event.connection)
                #       print "in connection..."
                #       log.debug('connected to switch %s',self.connections)

        
        
class l3switching(object):
        def __init__(self,connection):
                self.macaddrtable = {} #individual mac address table for each switch
                self.connection = connection
                connection.addListeners(self)

        def _handle_PacketIn(self,event):

                eth_packetRecv = event.parsed
                if eth_packetRecv.type == ethernet.ARP_TYPE: #checking if the payload is ARP pkt
                        msg = of.ofp_packet_out()
                        msg.in_port = event.port
                        arpreq = eth_packetRecv.payload # extract arp packet - arpreq
#                       log.debug('%s arp table',ARPTable)
                        if arpreq.protosrc not in ARPTable.keys(): #if no srcip entry in ARP table,add a new entry for scrip, srcmac
                                ARPTable[arpreq.protosrc] = arpreq.hwsrc
#                               print "in 1"
                        if arpreq.protodst not in ARPTable.keys():#if no entry in the ARPtable , then flood the ARP packet as l2 bc
                                eth_packetSent = eth_packetRecv
                                msg.data = eth_packetSent.pack()
                                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) #flooding on all ports of the swtch

                        elif arpreq.protodst in ARPTable.keys(): # if dstip in ARPTable,build appropriate ARP reply
                                arpreply = self.buildReply(arpreq)#building the arp reply ,
                                eth_packetSent = ethernet(type = ethernet.ARP_TYPE,dst = arpreply.hwdst )#setting type of ethernet packet and src and dst mac addresses
                                eth_packetSent.set_payload(arpreply) # the payload of the eth packet is the arp packet
                                msg.data = eth_packetSent.pack()
                                msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                                msg.in_port = event.port

                elif eth_packetRecv.type != ethernet.ARP_TYPE:
#                       print "in switching..."
                        msg = self.processPacket(event)
        #       log.debug('mac addr table %s',self.macaddrtable)
                event.connection.send(msg)

        def floodPacket(self,event):
                message = of.ofp_packet_out()
                message.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                message.data = event.data
                message.in_port = event.port
                return message
        
        def dropPacket(self,event):
                message = of.ofp_packet_out()
                message.data = event.data
                message.in_port = event.port
                return message

        def updateMap(self,srcportin,srcmacaddr):
                self.macaddrtable[srcmacaddr] = srcportin

        def processPacket(self,event):
                parsedpkt = event.parsed
                dstmacaddr = parsedpkt.dst
                srcmacaddr = parsedpkt.src
                self.updateMap(event.port,parsedpkt.src)
                if dstmacaddr.is_multicast:
                        msg = self.floodPacket(event)
                elif dstmacaddr not in self.macaddrtable:
                        msg = self.floodPacket(event)

                elif dstmacaddr in self.macaddrtable:
                        dstport = self.macaddrtable[dstmacaddr]
                        if dstport == event.port:
                                msg = self.dropPacket(event)
                        elif dstport != event.port:
                                msg = of.ofp_flow_mod()
                                msg.match = of.ofp_match.from_packet(parsedpkt,event.port)
                                msg.actions.append(of.ofp_action_output(port = dstport))
                                msg.data = event.ofp

                return msg


        def buildReply(self,arpreq):
                #feilds in arp packet [HWTYPE,PROTOTYPE,HWSRC,HWDST,HWLEN,OPCODE,PROTOLEN,PROTOSRC,PROTODST,NEXT]
                # will frame a new packet by calling packet.arp() as arp 

                arpreply = arp() #arpreply is object of type arp. now we can asign values to each feild
                arpreply.hwtype = arpreq.hwtype #which is basically 1 arp.HW_TYPE_ETHERNET
                arpreply.prototype = arpreq.prototype # 0x0800,arp.PROTO_TYPE_IP
                arpreply.hwsrc = EthAddr(ARPTable[arpreq.protodst]) #proxying for real destination
                arpreply.hwdst = arpreq.hwsrc # replying back to the src , hence dst is src
                arpreply.hwlen=6 #len of mac add
                arpreply.opcode=arp.REPLY #2
                arpreply.protolen=4 #len of ip add
                arpreply.protosrc= arpreq.protodst #proxying on behalf of dest
                arpreply.protodst = arpreq.protosrc #replying back to src
                return arpreply

def launch():
        core.registerNew(L3Component)
