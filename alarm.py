#!/usr/bin/python3

from scapy.all import *
import argparse
import base64
import re

incident_num = 1
user = ""
pword = ""

def packetcallback(packet):
  global incident_num
  global user
  global pword
  try:
    src = packet['IP'].src
    flags = packet['TCP'].flags
    payload = packet['TCP'].load.decode("ascii").strip()

    # NULL scan
    if flags == []:
      print("ALERT "+ str(incident_num)+ ": NULL Scan Detected from "+src)
      incident_num = incident_num + 1
    
    # FIN scan
    if flags == ['F']:
      print("ALERT "+ str(incident_num)+ ": FIN Scan Detected from "+src)
      incident_num = incident_num + 1
    
    # Xmas scan
    if 'F' in flags and 'P' in flags and 'U' in flags:
      print("ALERT "+ str(incident_num)+ ": XMAS Scan Detected from "+src)
      incident_num = incident_num + 1

    # Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
    # FTP Credentials
    if packet['TCP'].dport == 21:
      payload = packet['TCP'].load.decode("ascii").strip()
      if "USER" in payload:
        user = re.findall("USER.*", payload)[0].replace("USER ", "").replace("\r", "")
      if "PASS" in payload:
        pword = re.findall("PASS.*", payload)[0].replace("PASS ", "").replace("\r", "")
      if user != "" and pword != "":
        print("ALERT "+ str(incident_num)+ ": Usernames and passwords sent in-the-clear (FTP) from "+src+" (username:"+user+ " password:"+pword+")")
        incident_num = incident_num + 1
        user = ""
        pword = ""
      
    # HTTP Credentials
    if "HTTP" in payload:
      if "Basic" in payload:
        credentials = base64.b64decode(re.findall("Authorization: Basic.*", payload)[0].replace("Authorization: Basic ", "").replace("\r", "")).decode('utf-8').split(":")
        print("ALERT "+ str(incident_num)+ ": Usernames and passwords sent in-the-clear (HTTP) from "+src+" (username:"+credentials[0]+ " password:"+credentials[1]+")")
        incident_num = incident_num + 1
    
    # IMAP Credentials
    if packet['TCP'].dport == 143:
      if "LOGIN" in payload:
        credentials = re.findall("LOGIN.*", payload)[0].replace("LOGIN ", "").replace(" \"", ":").replace("\"", "").replace("\r", "").split(":")
        print("ALERT "+ str(incident_num)+ ": Usernames and passwords sent in-the-clear (IMAP) from "+src+" (username:"+credentials[0]+ " password:"+credentials[1]+")")
        incident_num = incident_num + 1
    
    # Nikto scan
    if "Nikto" in payload:
      print("ALERT "+ str(incident_num)+ ": Nikto Scan Detected from "+src)
      incident_num = incident_num + 1

    # Someone scanning for Server Message Block (SMB) protocol
    if packet['TCP'].dport == 139 or packet['TCP'].dport == 445:
      print("ALERT "+ str(incident_num)+ ": Server Message Block Scan (SMB) Detected from "+src)
      incident_num = incident_num + 1

    # Someone scanning for Remote Desktop Protocol (RDP)
    if packet['TCP'].sport == 3389:
      print("ALERT "+ str(incident_num)+ ": Remote Desktop Protocol Scan (RDP) Detected from "+src)
      incident_num = incident_num + 1

    # Someone scanning for Virtual Network Computing (VNC) instance(s)
    if packet['TCP'].sport == 5900:
      print("ALERT "+ str(incident_num)+ ": Virtual Network Computing Scan (VNC) Detected from "+src)
      incident_num = incident_num + 1

  except Exception as e:
    # print(e)
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
