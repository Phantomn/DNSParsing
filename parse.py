import socket
from dnslib import DNSRecord

import socket
from dnslib import DNSRecord

def parse_dns_response(hex_stream):
    eth_header_length = 14

    # Convert hex_stream to bytes
    byte_stream = bytes.fromhex(hex_stream)

    ip_header_length = (byte_stream[eth_header_length] & 0x0F) * 4
    udp_header_length = 8

    dns_payload_start = eth_header_length + ip_header_length + udp_header_length
    dns_payload_bytes = byte_stream[dns_payload_start:]

    # Parse DNS payload
    dns_msg = DNSRecord.parse(dns_payload_bytes)

    # Access DNS header properties
    transaction_id = dns_msg.header.id
    qr = dns_msg.header.qr  # Query/Response Flag
    opcode = dns_msg.header.opcode  # Opcode
    aa = dns_msg.header.aa  # Authoritative Answer Flag
    tc = dns_msg.header.tc  # Truncated Flag
    rd = dns_msg.header.rd  # Recursion Desired Flag
    ra = dns_msg.header.ra  # Recursion Available Flag
    z = dns_msg.header.z  # Reserved Flag (Zero)
    rcode = dns_msg.header.rcode  # Response Code
    
    # Print DNS header information
    print("Transaction ID:", hex(transaction_id))
    #print("QR:", qr)
    #print("Opcode:", opcode)
    #print("AA:", aa)
    #print("TC:", tc)
    #print("RD:", rd)
    #print("RA:", ra)
    #print("Z:", z)
    #print("RCODE:", rcode)

    record_types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        15: "MX",
        28: "AAAA",
        # Add more record types as needed
    }
    # Access DNS questions
    questions = dns_msg.questions
    print("Questions:")
    for question in questions:
        qname = str(question.qname)
        qtype = question.qtype
        qclass = question.qclass
        print(f"  QNAME: {qname}")
        print(f"  QTYPE: {record_types.get(qtype, 'Unknown')}")
        print(f"  QCLASS: {qclass}")

    # Access DNS answers
    answers = dns_msg.rr
    print("Answers:")
    for answer in answers:
        name = str(answer.rname)
        rtype = answer.rtype
        rclass = answer.rclass
        ttl = answer.ttl
        rdata = str(answer.rdata)
        print(f"  NAME: {name}")
        print(f"  Type: {record_types.get(rtype, 'Unknown')}")
        print(f"  CLASS: {rclass}")
        print(f"  TTL: {ttl}")
        print(f"  RDATA: {rdata}")
        print()

    return dns_payload_bytes


hex_stream = "d46d6d1e2b52909f334789f4080045000190122d00003811977108080808c0a807070035ff52017ca1d259ae818000010008000000000e636f7265736563323031312d6d790a7368617265706f696e7403636f6d0000010001c00c000500010000092c000e0b636f726573656332303131c01bc03b0005000100000e1000270c323232302d6970763476366505636c756d700b6470726f646d67643130360561612d7274c01bc055000500010000003c00160e3139363132342d69707634763665046661726dc068c088000500010000003c00410e3139363132342d69707634763665046661726d0b6470726f646d6764313036107368617265706f696e746f6e6c696e6503636f6d06616b61646e73036e657400c0aa000500010000012c004f0d3139363132342d697076347636046661726d0b6470726f646d67643130360561612d72740a7368617265706f696e7403636f6d0d6475616c2d73706f2d303030330a73706f2d6d7365646765c0e6c0f700050001000000f00002c12bc12b00010001000000f000040d6b8808c12b00010001000000f000040d6b8a08"
response = parse_dns_response(hex_stream)

# Access and print DNS payload bytes if needed
#print("DNS Payload Bytes:", response)
