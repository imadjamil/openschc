import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from scapy.all import *
import binascii
import gen_rulemanager as RM
import compr_parser as parser
from compr_core import *

import pprint
import socket

tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tunnel.bind(("0.0.0.0", 0x5C4C))

class debug_protocol:
    def _log(*arg):
        print (arg)

parse = parser.Parser(debug_protocol)
rm    = RM.RuleManager()
rm.Add(file="icmp.json")
rm.Print()

comp = Compressor(debug_protocol)

def processPkt(pkt):
    global parser
    global rm
    
    #print(binascii.hexlify(bytes(pkt)))

    pkt_fields, data, err = parse.parse( bytes(pkt), T_DIR_DW, layers=["IP", "ICMP"], start="IPv6")
    print (pkt_fields)

    if pkt_fields != None:
        rule, device = rm.FindRuleFromPacket(pkt_fields, direction=T_DIR_DW)
        if rule != None:
            schc_pkt = comp.compress(rule, pkt_fields, data, T_DIR_DW)
            if device.find("udp") == 0:
                destination = (device.split(":")[1], int(device.split(":")[2]))
                print (destination)
                tunnel.sendto(schc_pkt._content, destination)
            else:
                print ("unknown connector" + device)

        

    


sniff(prn=processPkt, iface="he-ipv6")
 
