# Ben Carroll CS 460
# NOTE: this program will produce the correct answers. It will take a minute to run though

import sys
import dpkt
import socket

f = open(sys.argv[1])
pcap = dpkt.pcap.Reader(f)
ipInfo = {}

# This method will convert inet to and ip string
# There is a very similar example method in the dpkt Github repo
def ipToString(ip):
	try:
		return socket.inet_ntop(socket.AF_INET, ip)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, ip)

for ts, buf in pcap:
	try:
		eth = dpkt.ethernet.Ethernet(buf)

		# check to see if the packet uses IP and TCP
		if type(eth.data) != dpkt.ip.IP:	continue
		ip = eth.data
		if type(ip.data) != dpkt.tcp.TCP:	continue
		tcp = ip.data

		# extract flags from TCP data
		synFlag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
		ackFlag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0

		# get IP addresses
		ipSrc = ipToString(ip.src)
		ipDst = ipToString(ip.dst)

		# if there is a SYN+ACK packet update the SYN+ACK count for the dst address
		if synFlag and ackFlag:
			if ipDst not in ipInfo:
				ipInfo[ipDst] = (0, int(synFlag and ackFlag))
			else:
				ipInfo[ipDst] = (ipInfo[ipDst][0], ipInfo[ipDst][1]+int(synFlag and ackFlag))

		# if there is a SYN packet update the SYN count for the src address
		if synFlag and ackFlag == False:
			if ipSrc not in ipInfo:
				ipInfo[ipSrc] = (int(synFlag), 0)
			else:
				ipInfo[ipSrc] = (ipInfo[ipSrc][0]+int(synFlag), ipInfo[ipSrc][1])
	
	# if a packet throws a parsing expection, ignore that packet
	except dpkt.dpkt.NeedData:
		pass

# iterate through the ips and print those that satisfy our threat condition
for ip in ipInfo.keys():
	synCount = ipInfo[ip][0]
	synAckCount = ipInfo[ip][1]

	# Here abs(synCount-synAckCount) > 2 will check to see if the SYN and SYN+ACK difference is
	# big enough to put the ip under suspision
	if ipInfo[ip][0] > 3*ipInfo[ip][1] and abs(synCount-synAckCount) > 2:
		print ip
