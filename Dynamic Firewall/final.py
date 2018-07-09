#Nash Baughn
#nbaughn@ucsc.edu

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController

class final_topo(Topo):
	def build(self):
		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		s3 = self.addSwitch('s3')
		s4 = self.addSwitch('s4')
		s5 = self.addSwitch('s5')
		
		h1 = self.addHost('h1',mac='00:00:00:00:00:01',ip='10.1.1.10/24',defaultRoute="h1-eth0")
		h2 = self.addHost('h2',mac='00:00:00:00:00:02',ip='10.2.2.20/24',defaultRoute="h2-eth0")
		h3 = self.addHost('h3',mac='00:00:00:00:00:03',ip='10.3.3.30/24',defaultRoute="h3-eth0")
		h4 = self.addHost('h4',mac='00:00:00:00:00:04',ip='123.45.67.89/24',defaultRoute="h4-eth0")
		h5 = self.addHost('h5',mac='00:00:00:00:00:05',ip='10.5.5.50/24',defaultRoute="h5-eth0")

		
		self.addLink(s1,h1, port1=8, port2=0)
		self.addLink(s2,h2, port1=8, port2=0)
		self.addLink(s3,h3, port1=8, port2=0)
		self.addLink(s4,h4, port1=8, port2=0)
		self.addLink(s5,h5, port1=8, port2=0)


		self.addLink(s4,s1, port1=1, port2=1)
		self.addLink(s4,s2, port1=2, port2=1)
		self.addLink(s4,s3, port1=3, port2=1)
		self.addLink(s4,s5, port1=5, port2=1)

	def drop(self, packet, packet_in):
		msg = of.ofp_flow_mod()
		msg.match=of.ofp_match.from_packet(packet)
		msg.idle_timeout = 30
		msg.hard_timeout = 60
		msg.data = packet_in #no action = drop
		self.connection.send(msg)

	def forward (self, packet, packet_in, outport):
		msg = of.ofp_flow_mod()
		msg.match=of.ofp_match.from_packet(packet)
		msg.idle_timeout = 30
		msg.hard_timeout = 60
		msg.data = packet_in
		action = of.ofp_action_output(port=outport)
		msg.actions.append(action)
		self.connection.send(msg)

def configure():
	topo = final_topo()
	net = Mininet(topo=topo, controller=RemoteController)
	net.start()

	CLI(net)
  
	net.stop()

if __name__ == '__main__':
  configure()

