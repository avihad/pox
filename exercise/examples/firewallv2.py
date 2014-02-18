##################################

#author -durga
#controller - pox
#The below L2 firewall controllerinserts flow table entries as soon as a connectionUp event is triggered. 
#v3 tries to make the firewall appication reactive, by inserting the flow mod only during a packetIn event, 
#but since the l2 switching appliation too seems to be processing the packet, an buffer already in use related error is thrown at the user. 
#To circumvent the issue, the below code inserts higher priority flowtable entry as soon as a connection is made, avoiding the contention of buffer in total.
# this peice of code needs to be run along with the switching code (l2 switching ) 
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
from pox.lib.addresses import EthAddr

log = core.getLogger()

class l2_Firewall(EventMixin):
        def __init__(self):
                self.listenTo(core.openflow)

         def _handle_ConnectionUp(self,event):#everytime a connection is established, flow table modification messages are sent.
                print "in firewll"
                filterlist = [('00:00:00:00:00:02','00:00:00:00:00:03')]

                msg = of.ofp_flow_mod()
                msg.match.dl_src = EthAddr(filterlist[0][0])
                msg.match.dl_dst = EthAddr(filterlist[0][1])
                msg.priority = 65535
                event.connection.send(msg)


def launch():
        print "in launch.."
        core.registerNew(l2_Firewall) #registering the component to the core


