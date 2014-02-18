# author - durga
#copyright John McCauley , POX
# this program emulates a dumb hub on POX
# the POX controller inserts a flood all flow table entry into the switch forwarding table

from pox.lib import *
from pox.lib.revent import *
from pox.core import core
from pox.openflow import libopenflow_01 as of
import pox


class HUB ():
#class HUB can be inherited from EventMixin in case it is listening to multiple events, also in case listenTo() method is used instead of addListeners() as below
#class HUB(EventMixin):

        def __init__(self):
                core.openflow.addListeners(self) #listening to the openflow events
                #self.listenTo(core.openflow)
        def _handle_ConnectionUp(self,event): #handling the openflow events
                msg = of.ofp_flow_mod()
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                event.connection.send(msg)


def launch():
        core.registerNew(HUB) #launching the HUB component by registering it to core
        #core.openflow.addListenerByName("ConnectionUp",HUB._handle_ConnectionUp)
