#!/usr/bin/env python

import sys, os, platform, subprocess, threading, time, urllib
from datetime import datetime, timedelta

ping_results = []
netbios_results = []
oui_db = {}

class netbios_thread(threading.Thread):
	def __init__(self, ip):
		threading.Thread.__init__(self)
		self.ip = ip
		
	def run(self):
		_NULL = open(os.devnull, 'wb')
		if platform.system() == "Windows":
			nbtstat_proc = subprocess.Popen(['nbtstat', '-A', str(self.ip)], stdout=subprocess.PIPE)
		elif platform.system() == "Linux":
			nbtstat_proc = subprocess.Popen(['nmblookup', '-A', str(self.ip)], stdout=subprocess.PIPE)

		out, err = nbtstat_proc.communicate()
			
		for line in out.split("\n"):
			if not "GROUP" in line:
				if "<00>" in line: # Looking for "Workstation Service"
					r = line.strip().split()
					netbios_results.append([self.ip, r[0].replace("<00>","")])
			
class ping_thread(threading.Thread):
	def __init__(self, ip):
		threading.Thread.__init__(self)
		self.ip = ip
		
	def run(self):
		_NULL = open(os.devnull, 'wb')
		if platform.system() == "Windows":
			subprocess.Popen(["ping", "-n", "2", str(self.ip)], stdout=_NULL, stderr=_NULL)
		elif platform.system() == "Linux":
			subprocess.Popen(["ping", "-c", "2", str(self.ip)], stdout=_NULL, stderr=_NULL)

def get_path():
	path, _ = os.path.split(os.path.realpath(__file__))
	return path

def download_oui_txt():
	print "Downloading oui.txt..."
	#FIXME: Check for download errors
	urllib.urlretrieve ("https://standards.ieee.org/develop/regauth/oui/oui.txt", get_path() + "/oui.txt")

def oui_lookup(mac):
	return oui_db[mac.upper()]

def tabulate(data, headers):
	#FIXME: this is messy..

	if len(headers) != len(data[0]):
		print "header and data dimension mismatch"
		return

	# determine longest data fields
	d_len = [None] * len(data[0])
	for i in data:
		if len(i[0]) > d_len[0]:
			d_len[0] = len(i[0])
		if len(i[1]) > d_len[1]:
			d_len[1] = len(i[1])
		if len(i[2]) > d_len[2]:
			d_len[2]= len(i[2])
		if len(i[3]) > d_len[3]:
			d_len[3] = len(i[3])

	# determine length of headers
	h_len = [None] * len(headers)
	for i in range(len(headers)):
		h_len[i] = len(headers[i])

	# find max length per column
	col_len = [None] * len(d_len) #or len(h_len) as it is the same len as d_len
	for i in range(len(d_len)):
		if h_len[i] > d_len[i]:
			col_len[i] = h_len[i]
		else:
			col_len[i] = d_len[i]

	# print headers
	print "| " + headers[0] + (" " * (col_len[0] - h_len[0])),
	print "| " + headers[1] + (" " * (col_len[1] - h_len[1])),
	print "| " + headers[2] + (" " * (col_len[2] - h_len[2])),
	print "| " + headers[3] + (" " * (col_len[3] - h_len[3])) + " |"

	# print separator
	print "|" + ("-" * (col_len[0]+2)) + "+" + ("-" * (col_len[1]+2)) + "+" + ("-" * (col_len[2]+2)) + "+" + ("-" * (col_len[3]+2)) + "|" 

	# print results
	for i in data:
		print "| {0:<{l0}} | {1:<{l1}} | {2:<{l2}} | {3:<{l3}} |".format(i[0], i[1], i[2], i[3], l0=col_len[0], l1=col_len[1], l2=col_len[2], l3=col_len[3])


if __name__ == '__main__':
	print "ipscan.py 0.9 <https://github.com/omerk/ipscan>\n"

	ping_threads = []
	netbios_threads = []
	
	# Ensure that oui.txt exists and it is not older than 2 weeks
	if os.path.exists(get_path() + "/oui.txt"):
		filetime = datetime.fromtimestamp(os.path.getmtime(get_path() + "/oui.txt"))
		if filetime < (datetime.now() - timedelta(weeks=2)):
			download_oui_txt()
	else:
		download_oui_txt()
	
	# Parse oui.txt and build oui_db
	print "Parsing oui.txt..."
	oui_txt = open(get_path() + "/oui.txt", 'r')
	for line in oui_txt:
		if 'base 16' in line:
			oui_db[line[:8].strip()] = line[23:].strip()

	# Start pinging hosts
	print "Pinging hosts..."
	# FIXME: Get IP range from argv
	for x in range(254):
		ping_threads.append(ping_thread("192.168.0." + str(x)))

	[t.start() for t in ping_threads]
	# Wait for completion
	[t.join() for t in ping_threads]

	# Wait for the ARP cache to settle(??)
	print "Parsing ARP cache..."
	time.sleep(5)

	# Go through the ARP cache
	if platform.system() == "Windows":
		arp_proc = subprocess.Popen(['arp', '-a'], stdout=subprocess.PIPE)
		out, err = arp_proc.communicate()
	
		# Pick hosts and dump then in the results array
		for line in out.split("\n"):
			if 'dynamic' in line:
				r = line.strip().split()
				ping_results.append([r[0], "-", r[1], oui_lookup(r[1][:8].replace("-",""))])
	elif platform.system() == "Linux":
		arp_proc = subprocess.Popen(['cat', '/proc/net/arp'], stdout=subprocess.PIPE)
		out, err = arp_proc.communicate()

		# Pick hosts and dump then in the results array
		for line in out.split("\n"):
			if '0x2' in line:
				r = line.strip().split()
				ping_results.append([r[0], "-", r[3], oui_lookup(r[3][:8].replace(":",""))])

	# Create the list of threads for the Netbios scan
	for r in ping_results:
		netbios_threads.append(netbios_thread(r[0]))
	
	# Query Netbios names
	print "Resolving Netbios names..."
	[t.start() for t in netbios_threads]
	# Wait for completion
	[t.join() for t in netbios_threads]
		
	# Match ping and netbios scan results
	# there has to be a better way of doing this...
	for p in ping_results:
		for n in netbios_results:
			if p[0] == n[0]:
				p[1] = n[1]

	# Print results
	print "\nTotal hosts found: %d\n" % len(ping_results)
	print tabulate(ping_results, ["IP", "Netbios Name", "MAC", "Vendor"])

