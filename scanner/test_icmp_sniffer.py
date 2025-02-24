import ipaddress
import os
import socket
import struct
import sys

class IP:
    def __init__(self, buff):
        header = struct.unpack('!BBHHHBBH4s4s', buff)  # ! işareti network byte order için değiştirildi
        self.ver = header[0] >> 4  
        self.ihl = header[0] & 0xF  
        self.tos = header[1]  
        self.len = header[2]  
        self.id = header[3]  
        self.offset = header[4]  
        self.ttl = header[5]  
        self.protocol_num = header[6]  
        self.sum = header[7]  
        self.src = header[8]  
        self.dst = header[9]  

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('!BBHHH', buff)  # ! işareti eklendi
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    try:
        # RAW soket oluştur ve ICMP paketlerini dinle
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sniffer.bind((host, 0))

        # Linux için IP header'ı dahil etmeye gerek yok
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print(f"[*] Sniffing ICMP packets on {host}...")

        while True:
            raw_buffer, _ = sniffer.recvfrom(65535)
            ip_header = IP(raw_buffer[:20])

            if ip_header.protocol == "ICMP":
                print(f"[*] ICMP Packet: {ip_header.src_address} -> {ip_header.dst_address}")
                print(f"    Version: {ip_header.ver}, Header Length: {ip_header.ihl}, TTL: {ip_header.ttl}")

                offset = ip_header.ihl * 4
                icmp_header = ICMP(raw_buffer[offset:offset + 8])
                print(f"    ICMP -> Type: {icmp_header.type}, Code: {icmp_header.code}, ID: {icmp_header.id}, Seq: {icmp_header.seq}\n")

    except KeyboardInterrupt:
        print("\n[!] Sniffer durduruldu.")
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.19'

    sniff(host)
