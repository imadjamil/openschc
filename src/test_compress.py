from gen_base_import import b2hex
from compr_core import *
from compr_parser import *
from gen_rulemanager import *

import binascii


class debug_protocol:
    def _log(*arg):
        print(*arg)


p = Parser(debug_protocol)

coap = bytearray(
    b"""`\
\x12\x34\x56\x00\x1e\x11\x1e\xfe\x80\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x02\x16\
2\x163\x00\x1e\x00\x00A\x02\x00\x01\n\xb3\
foo\x03bar\x06ABCD==Fk=eth0\xff\x84\x01\
\x82  &Ehello"""
)

print(f"{coap}")
print(f"{b2hex(coap)=}")
print(f"{int.from_bytes(coap, 'big').bit_length()=}")

v = p.parse(pkt=coap, direction=T_DIR_UP)  # or T_DIR_DW
print("parsed headers:")
print(v[0])
print(f"non-parsed data: {v[1]}")

RM = RuleManager(log=debug_protocol)
RM.Add(file="examples/configs/comp-rule-100_test.json")
# RM.Print()

C = Compressor(debug_protocol)
D = Decompressor(debug_protocol)

r, dev_id = RM.FindRuleFromPacket(v[0], direction="UP")
if r != None:
    # print("selected rule is ", r)
    schc_packet = C.compress(rule=r, parsed_packet=v[0], data=v[1], direction=T_DIR_UP)

    print(f"{schc_packet=}")
    # print(f"{schc_packet.get_length()=}")
    # schc_packet.display("bin")

    rbis = RM.FindRuleFromSCHCpacket(schc=schc_packet)
    #
    if rbis != None:
        pbis = D.decompress(schc=schc_packet, rule=rbis, direction=T_DIR_UP)
        print("decompressed headers:")
        print(pbis)
