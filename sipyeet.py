#!/usr/bin/env python3

from scapy.all import *
import argparse
import string
from random import choices

parser = argparse.ArgumentParser()
parser.add_argument("-sp", type=int, default=5060, help="The source port")
parser.add_argument("-dp", type=int, default=5060, help="The destination port")
parser.add_argument("-tt", action="store_true", help="Transport TCP")
parser.add_argument("-dst", default="127.0.0.2", help="The destination IP")
parser.add_argument("-src", default="127.0.0.1", help="The source IP")
parser.add_argument("-fuser", type=str, default="yeet", help="SIP FROM User")
parser.add_argument("-tuser", type=str, default="yoink", help="SIP TO User")

parser.add_argument("--no-rfc3261-branches", action="store_false", help="Don't use the 'z9hG4bK'-prefix in Via/Branch. See https://tools.ietf.org/html/rfc3261#section-8.1.1.7")

# Flow related arguments
parser.add_argument("--dry-run", action="store_true", help="Don't actually send pakets.")
parser.add_argument("-v", action="store_true", help="Be more verbose about the yeetage.")

parser.parse_args()
args = parser.parse_args()

sourcePort = args.sp
destinationPort = args.dp
destinationIp = args.dst
sourceIp = args.src

sipTag = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
sipBranch = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

if args.no_rfc3261_branches:
    sipBranch = ("z9hG4bK{0}".format(sipBranch))


if args.tt:
    transport = "tcp"
else:
    transport = "udp"

ip=IP(src=sourceIp, dst=destinationIp)

myPayload=(
    'OPTIONS sip:{0}:{1};transport={6} SIP/2.0\r\n'
    'Via: SIP/2.0/{7} {2}:{3};branch={8}\r\n'
    'From: \"{4}\"<sip:{4}@{2}:{3}>;tag={9}\r\n'
    'To: \"{5}\" <sip:{5}@{0}:{1}>\r\n'
    'Call-ID: 9abcd\r\n'
    'CSeq: 1 OPTIONS\r\n'
    'Max-Forwards: 0\r\n'
    'Content-Length: 0\r\n\r\n').format(destinationIp, destinationPort, sourceIp, sourcePort, 
        args.fuser, args.tuser, transport, transport.upper(), sipBranch, sipTag)

if args.v:
    print("Payload to be yeeted:")
    print(myPayload)

if not args.dry_run:
    if args.tt:
        # TCP SYN
        TCP_SYN=TCP(sport=sourcePort, dport=destinationPort, flags="S", seq=100)
        TCP_SYNACK=sr1(ip/TCP_SYN)

        # TCP SYN+ACK
        myAck = TCP_SYNACK.seq + 1
        TCP_ACK=TCP(sport=sourcePort, dport=destinationPort, flags="A", seq=101, ack=myAck)
        send(ip/TCP_ACK)

        TCP_PUSH=TCP(sport=sourcePort, dport=destinationPort, flags="PA", seq=101, ack=myAck)
        send(ip/TCP_PUSH/myPayload)
    else:
        UDP_PUSH=UDP(sport=sourcePort, dport=destinationPort)
        send(ip/UDP_PUSH/myPayload)
else:
    print("No SIP UA{C,S} where harmed 🙃")