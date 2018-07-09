#Nash Baughn
#nbaughn@ucsc.edu

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import time
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()

class Final (object):
	"""
	A Firewall object is created for each switch that connects.
	A Connection object for that switch is passed to the __init__ function.
	"""
	def __init__ (self, connection):
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)

	#generic foward method 
	def forward (self, packet, packet_in, outport):
		msg = of.ofp_flow_mod()
		msg.match=of.ofp_match.from_packet(packet)
		msg.idle_timeout = 30
		msg.hard_timeout = 60
		msg.data = packet_in
		action = of.ofp_action_output(port=outport)
		msg.actions.append(action)
		self.connection.send(msg)

	#generic drop method 
	def drop(self, packet, packet_in):
		msg = of.ofp_flow_mod()
		msg.match=of.ofp_match.from_packet(packet)
		msg.idle_timeout = 30
		msg.hard_timeout = 60
		msg.data = packet_in #no action = drop
		self.connection.send(msg)

	def do_final (self, packet, packet_in, port_on_switch, switch_id):
		#check packet using find() method to search for allowed protocols
		ip_header = packet.find('ipv4')
		tcp = packet.find('tcp')
		arp = packet.find('arp')
		icmp = packet.find('icmp')

		if ip_header is None:
			# not an IP packet so FLOOD!
			print "Flooding!"
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(packet)
			msg.idle_timeout = 30
			msg.hard_timeout = 60
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
			msg.data = packet_in
			self.connection.send(msg)
			return


		#for switches 1, 2, 3, 5 all the code is the same. Therefore all comments
		#for swtich 1 also apply to 2, 3, 5.
		if switch_id == 1:
			print "switch_id: " + str(switch_id)
			#if the packet is leaving h1 then it gets fowarded to s4 through port 0
			if ip_header.srcip == "10.1.1.10" and ip_header.dstip != "123.45.67.89":
				print "srcip: " + str(ip_header.srcip)
				#foward packet to s4
				self.forward(packet, packet_in, 1)

			#if the packet is arriving at h1 then it gets fowarded to h1 through port 8 on s1
			if ip_header.dstip == "10.1.1.10":
				print "dstip: " + str(ip_header.dstip)
				#foward packet to the correct host
				self.forward(packet, packet_in, 8)
	
		elif switch_id == 2: 
			print "switch_id: " + str(switch_id)
			if ip_header.srcip == "10.2.2.20" and ip_header.dstip != "123.45.67.89":
				print "srcip: " + str(ip_header.srcip)
				self.forward(packet, packet_in, 1)

			if ip_header.dstip == "10.2.2.20":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 8)

		elif switch_id == 3:
			print "switch_id: " + str(switch_id)
			if ip_header.srcip == "10.3.3.30" and ip_header.dstip != "123.45.67.89":
				print "srcip: " + str(ip_header.srcip)
				self.forward(packet, packet_in, 1)

			if ip_header.dstip == "10.3.3.30":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 8)

		elif switch_id == 5:  
			print "switch_id: " + str(switch_id)
			if ip_header.srcip == "10.5.5.50" and ip_header.dstip != "123.45.67.89":
				print "srcip: " + str(ip_header.srcip)
				self.forward(packet, packet_in, 1)
			
			if ip_header.dstip == "10.5.5.50":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 8)

		#s4 is the intermmediate hop between h1, h2, h3, h5 and also the connection
		#between h4 (the untrusted host) and the network.
		elif switch_id == 4:
			
			print "switch_id: " + str(switch_id)
			#Check if packet is from h4 in addition to of it is ICMP
			if ip_header.srcip == "123.45.67.89"  and packet.find('icmp') is not None:
					print "Blocking ICMP from UNTRUSTED host"
					#drop ICMP traffic from h4
					self.drop(packet, packet_in)
					return
			#Check if packet is from h4 in addition to if its destination is the server
			if ip_header.srcip == "123.45.67.89"  and ip_header.dstip == "10.5.5.50": 
					print "Blocking ALL IP traffic to server from UNTRUSTED host"
					#drop server request traffic from h4
					self.drop(packet, packet_in)
					return

			#foward packet from s4 to correct switch
			if ip_header.dstip == "10.1.1.10":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 1)
					
			elif ip_header.dstip == "10.2.2.20":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 2)
				
			elif ip_header.dstip == "10.3.3.30":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 3)
				
			elif ip_header.dstip == "10.5.5.50":
				print "dstip: " + str(ip_header.dstip)
				self.forward(packet, packet_in, 5)
				
		print "---------------\n"
	
	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""
		packet = event.parsed # This is the parsed packet data.
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		packet_in = event.ofp # The actual ofp_packet_in message.
		self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Final(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
