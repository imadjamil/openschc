import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from scapy.all import *

import gen_rulemanager as RM
from protocol import SCHCProtocol
from scapy_connection import *
from gen_utils import dprint, sanitize_value
from compr_parser import Unparser
from scapy.layers.inet import IP
#from scapy.layers.inet6 import IPv6

import pprint
import binascii
import socket
import ipaddress


# Create a Rule Manager and upload the rules.
rm = RM.RuleManager()
rm.Add(file="icmp3.json")
rm.Print()

unparser = Unparser()

def processPkt(pkt):
    """ called when scapy receives a packet, since this function takes only one argument,
    schc_machine and scheduler must be specified as a global variable.
    """
    scheduler.run(session=schc_machine)

    # look for a tunneled SCHC pkt
    if pkt.getlayer(Ether) != None: #HE tunnel do not have Ethernet
        e_type = pkt.getlayer(Ether).type
        print(f"{e_type=}")
        if e_type == 0x0800:
            ip_proto = pkt.getlayer(IP).proto
            print(f"{ip_proto=}")
            if ip_proto == 17:
                udp_dport = pkt.getlayer(UDP).dport
                print(f"{udp_dport=}")
                if udp_dport == socket_port: # tunnel SCHC msg to be decompressed
                    print ("tunneled SCHC msg")                    
                    schc_pkt, addr = tunnel.recvfrom(2000)
                    other_end = "udp:"+addr[0]+":"+str(addr[1])
                    print("other end =", other_end)
                    uncomp_pkt = schc_machine.schc_recv(core_id=core_id, device_id=other_end, schc_packet=schc_pkt)                       
                    if uncomp_pkt != None:
                        uncomp_pkt[1].show()
                        send(uncomp_pkt[1], iface="he-ipv6") 
            elif ip_proto==41:
                print(f"ipv6 detected ...")
                schc_machine.schc_send(bytes(pkt)[34:], device_id=device_id, core_id=core_id, sender_delay=0)
        elif e_type == 0x86DD:
            print(f"untunneled ipv6 detected ...")
            schc_machine.schc_send(bytes(pkt)[14:], device_id=device_id, core_id=core_id, sender_delay=0)


# Start SCHC Machine
POSITION = T_POSITION_CORE

socket_port = 0x5C4C
print(f"{socket_port=}")
ip = "127.0.0.1"
core_id = "udp:"+ip+":"+str(socket_port)
device_id = rm._ctxt[0]["DeviceID"]
tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tunnel.bind(("0.0.0.0", socket_port))

lower_layer = ScapyLowerLayer(position=POSITION, socket=tunnel, other_end=None)
system = ScapySystem()
scheduler = system.get_scheduler()
schc_machine = SCHCProtocol(
    system=system,           # define the scheduler
    layer2=lower_layer,      # how to send messages
    role=POSITION,           # DEVICE or CORE
    verbose = True)         
schc_machine.set_rulemanager(rm)

sniff(prn=processPkt, iface="lo") # scappy cannot read multiple interfaces

