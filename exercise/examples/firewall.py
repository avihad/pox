##################################

#author -durga
#controller - pox

#The  controller inserts flow table entries based on switching rules
# following code emulates basic source-mac address learning,forwarding
#and filtering mechanisms found on switches
#1.keep firewall policy in place
# Th the firewall filters based on Mac addr, IP adr and TCP headers (for XMAS attacks)

#2.if the incoming packet matches the firewall rules, follow the rule
#3.if a match and drop action, insert a flow table entry to drop the packet
#4. if no match or a forward action, process the packet as per normal switching action.
# L2 controller inserts the flow table entries based on switching rules
# the following code emulates basic source-mac address learning , forwarding
# 1.switch forwards any packet with no match to the controller
#   > controller to check if (src-mac-add ,src-port-id) pair be updated in the srcmacaddr table.
#   > if dest is a multicast - flood the packet
#   > controller to check for (des-mac-add,dest-port-id) pair in its addr table
#	>a. if an entry is made, send relevant flow mod message(with a match statement) to switch with information of outgoing port.
#	>b. if no entry is made, the controller insturcts the switch to  broadcast the packet for that destnation mac addr 
#	>c. if destination port addr is same as source port addr drop the packet#   > send the ofmessage to the out.

##################################
# generic info
# all mentioned events ex:ConnectionUp and PacketIn can be found in pox/openflow/__init__.py
# all events have min of 3 attributes 1. connection 2.ofp (of packet which triggerd the event) 3.dpid
#though there is no req for controller to maintain mac addr table, since the ft on switch expires its always a good idea to have a ref on controller -- macaddrtable{}
#in v5 version, trying to accomodate multiple switches.
###################################
#DDoS , DOS attacks are made when a host or set of hosts repeatedly sends ICMP/unneccessary to specific destination server, the server renders incapbale of handling any legitimate traffic. The following module of code would check the number of packets for a given destination in a duration of 1 min or so and blocks icmp packets to the destination host for a specific amount of time.
# below replicated module is ping flood.
###################################
from pox.lib import *
from  pox.core import core  # to import core module to register and hook the module
#from  pox.lib import packet as pkt #to import modules from packet
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
import os
from csv import DictReader

log = core.getLogger()

class l2_learning(EventMixin):
	def __init__(self,transparent):
		self.listenTo(core.openflow)
		self.transparent = transparent

	def _handle_ConnectionUp(self,event):#everytime a connection is established, a new switch instance is created
		L2firewall(event.connection,self.transparent)

class L2firewall(object):
	def __init__(self,connection,transparent):
	# as soon as the module is hooked initialise..
		self.macaddrtable = {}
		self.transparent = transparent
		self.connection = connection
		connection.addListeners(self)

	def _handle_PacketIn (self,event):
	 # event handler for incoming packets.check pox/openflow/__init__.py for infor on PacketIn(Event) class. ofp represents the real openflow packet which triggered the event and is an event attribute.
		self.processPacket(event)

	def checkRules(self,packet):
		rulefile = "%s/learn/IDS/rulesfile.csv" %os.environ['HOME']
		
		openrulesfile = open(rulefile,'rb')
		ruledict = DictReader(openrulesfile)
			
		#filterlist = [('00:00:00:00:00:02','00:00:00:00:00:03'),('00:00:00:00:00:01','00:00:00:00:00:07'),('10.0.0.1','10.0.0.3'),('10.0.0.1','10.0.0.3')]
		if packet.find('ethernet'):
			srcmac = str(packet.src)
			dstmac = str(packet.dst)
		if packet.find('ipv4') != None  or packet.find('ipv6') != None:
			if packet.find('ipv4') != None:
				ippkt = packet.find('ipv4')
			elif packet.find('ipv6') != None:
				ippkt = packet.find('ipv6') 
			srcip = str(ippkt.srcip)
			dstip = str(ippkt.dstip)
		if packet.find('tcp') != None :
			tcphdr = packet.find('tcp')
	# to check for XMAS attack where all tcp flags are set high.
			if tcphdr.FIN and tcphdr.SYN and tcphdr.RST and tcphdr.PSH and tcphdr.ACK and tcphrd.URG and tcphrd.ECN and tcphrd.CWR:
				return 'DROP'
			
		for rule in ruledict:
			
			if (srcmac == rule['src'] or srcmac == rule['dst'])  and  (dstmac == rule['src'] or dstmac == rule['dst']):
				#print the packets being dropped
				return 'DROP'
			elif packet.type == packet.IP_TYPE:
				if  (srcip == rule['src'] or srcip == rule['dst']) and (dstip == rule['src'] or dstip == rule['dst']):
				#print the packets being dropped
					return 'DROP'
			
	
		return 'SWITCH'

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
		log.debug("%i --> %s" ,event.dpid,parsedpkt)
		inport = event.port
		#log.debug("%s-->%s",inport,parsedpkt)
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

		elif self.checkRules(parsedpkt)=='DROP':
		#since no action is being set, the 'msg' will have a drop action

			pass

		elif dstmacaddr not in self.macaddrtable:#if destmac not in macaddrtable,flood
			msg = self.floodPacket(event)

		elif dstmacaddr in self.macaddrtable:# if dstmac in macaddrtable
			dstport = self.macaddrtable[dstmacaddr] #choose port
			if dstport == event.port: #if same as inport , drop the packet
				msg = self.dropPacket(event)
				print "dropping"
			elif dstport != event.port or self.checkRules(parsedpkt) == 'SWITCH': #else, insert a flow table entry
				msg.actions.append(of.ofp_action_output(port = dstport))
		#		log.debug ("%s"%msg)
		#
		self.sendFlowMod(msg,event)
		

def launch():
	print "in launch.."
	core.registerNew(l2_learning,False) #registering the component to the core














