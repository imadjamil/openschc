#!/usr/bin/env python

import sys
import signal
from argparse import ArgumentParser
from net_udp_core import (
    protocol,
    gen_rulemanager,
    UdpLowerLayer,
    UdpUpperLayer,
    UdpSystem,
)
import json


# read the set of rules (sor) form file
with open(f"../configs/rule_comp.json") as json_file:
    sor = json.load(json_file)

print(f"{sor=}")

coap_ip_packet = bytearray(
    b"""`\
\x12\x34\x56\x00\x1e\x11\x1e\xfe\x80\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x02\x16\
2\x163\x00\x1e\x00\x00A\x02\x00\x01\n\xb3\
foo\x03bar\x06ABCD==Fk=eth0\xff\x84\x01\
\x82  &Ehello"""
)

# The ` was deleted for the following to work,
# what is used for?
# coap_ip_packet = bytearray(
#     b"""\
# \x60\x00\x00\x00\x00\x1d\x11\x3f\x20\x01\
# \x05\xc0\x15\x08\xf3\x00\x14\x3f\xbd\x0e\
# \x4c\x65\xb1\xa6\x20\x01\x05\xc0\x15\x08\
# \xf3\x01\xc3\x0c\x00\x00\x00\x00\x13\xd8\
# \xf7\x20\x16\x33\x00\x1d\xdd\xab\x40\x01\
# \x47\xc0\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b\
# \x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65"""
# )
print(f"{coap_ip_packet=}")
# sys.exit()
#
# --------------------------------------------------
# Get UDP address and role from command line

parser = ArgumentParser()
parser.add_argument("role", choices=["device", "core", "core-server"])
args = parser.parse_args()

ip_address = ""
role = args.role
if role == "core":
    role = "core-server"

if role == "device":
    udp_src = (ip_address, 33300)
    udp_dst = (ip_address, 33333)
    rule_address = (ip_address, 33300)
else:
    assert role == "core-server"
    udp_src = (ip_address, 33333)
    udp_dst = (ip_address, 33300)
    rule_address = (ip_address, 33300)

# --------------------------------------------------
# Run SCHC

rule_manager = gen_rulemanager.RuleManager()
rule_manager.Add(dev_info=sor)
rule_manager.Print()

config = {}
upper_layer = UdpUpperLayer()
lower_layer = UdpLowerLayer(udp_src, udp_dst)
system = UdpSystem()
scheduler = system.get_scheduler()
schc_protocol = protocol.SCHCProtocol(
    config, system, layer2=lower_layer, layer3=upper_layer, role=role, unique_peer=True
)

schc_protocol.set_rulemanager(rule_manager)

if args.role == "device":
    # XXX: fix addresses mismatches
    upper_layer.send_later(1, udp_src, coap_ip_packet)

sys.stdout.flush()


# handle signal to stop the program
def signal_handler(sig_num, frame=None):
    # handles the Ctrl-C signal
    print("End of program requested")
    sys.exit(0)


# Handles the Ctrl-C signal
signal.signal(signal.SIGINT, signal_handler)

scheduler.run()
# --------------------------------------------------
