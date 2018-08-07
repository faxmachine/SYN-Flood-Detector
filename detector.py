#!/usr/bin/env python2
import sys
import dpkt
import socket

def ip_to_string(ip):
	"""
	Converts inet to an ip string
	There is a very similar example method in the dpkt Github repo
	"""
	try:
		return socket.inet_ntop(socket.AF_INET, ip)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, ip)

def populate_ip_info(ip_info):
	""" 
	Populates the ip_info dictionary with TCP flag information
	"""

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
			ipSrc = ip_to_string(ip.src)
			ipDst = ip_to_string(ip.dst)

			# if there is a SYN+ACK packet update the SYN+ACK count for the dst address
			if synFlag and ackFlag:
				if ipDst not in ip_info:
					ip_info[ipDst] = (0, int(synFlag and ackFlag))
				else:
					ip_info[ipDst] = (ip_info[ipDst][0], ip_info[ipDst][1]+int(synFlag and ackFlag))

			# if there is a SYN packet update the SYN count for the src address
			if synFlag and ackFlag == False:
				if ipSrc not in ip_info:
					ip_info[ipSrc] = (int(synFlag), 0)
				else:
					ip_info[ipSrc] = (ip_info[ipSrc][0]+int(synFlag), ip_info[ipSrc][1])
		
		# if a packet throws a parsing expection, ignore that packet
		except dpkt.dpkt.NeedData:
			pass

if __name__ == '__main__':
	f = open(sys.argv[1])
	pcap = dpkt.pcap.Reader(f)
	ip_info = {}

	print "extracting IP info... this might take a minute"
	populate_ip_info(ip_info)

	# iterate through the ips and print those that satisfy our threat condition
	print "suspicious IPs:"
	for ip in ip_info.keys():
		synCount = ip_info[ip][0]
		synAckCount = ip_info[ip][1]

		# Here abs(synCount-synAckCount) > 2 will check to see if the SYN and SYN+ACK difference is
		# big enough to put the ip under suspicion
		if ip_info[ip][0] > 3*ip_info[ip][1] and abs(synCount-synAckCount) > 2:
			print ip
