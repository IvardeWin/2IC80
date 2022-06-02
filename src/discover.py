from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether


class Discover(threading.Thread):

    def __init__(self, config: dict, interface: str):
        super(Discover, self).__init__()
        self.config = config
        self.interface = interface

    def stop(self):
        self._stop.set()

    def is_stopped(self):
        return self._stop.isSet()

    def run(self):
        self.passive()

    def local_host_discovered(self, mac: str, ip: str):
        """
        Add found host to the dictionary

            :param mac: The mac address of the discovered host
            :param ip: The ip address of the discovered host
        """
        hosts: dict = self.config["hosts"][self.interface]
        if mac not in hosts:
            hosts.update(dict({mac: {ip}}))
        elif ip not in hosts[mac]:
            hosts[mac].add(ip)


    def filter_host(self, mac: str, ip: str):
        """
        Filters out all unwanted hosts

        Args:
            :param mac: The mac address of a host 
            :param ip: The ip address of a host
        """
        if mac == "ff:ff:ff:ff:ff:ff":
            return # Filter out broadcasts
        # TODO filter out self
        # TODO filter out router?
        # TODO filter out non-local?
        self.local_host_discovered(mac, ip)


    def packet_sniffed(self, pkt: packet):
        """
        Retrieves the mac- and ip-address of hosts from sniffed packets

            :param pkt: The sniffed packet
        """
        if IP in pkt:
            self.filter_host(pkt[Ether].src, pkt[IP].src)
            self.filter_host(pkt[Ether].dst, pkt[IP].dst)
        if ARP in pkt:
            self.filter_host(pkt[Ether].src, pkt[ARP].psrc)
            self.filter_host(pkt[Ether].dst, pkt[ARP].pdst)


    def passive(self):
        """
        Passively sniffs packets on the current interface
        """
        try:
            #sniff(iface=self.interface, count=0, store=0, prn=self.packet_sniffed)
            sniff(count=0, store=0, prn=self.packet_sniffed)
        except OSError:
            print(f"Could not open the adapter for interface {self.interface}")
            self.stop()
        except Scapy_Exception:
            print(f"Could not operate on interface {self.interface}")
            self.stop()
        except IndexError:
            print(f"Layer not found")
            self.stop()

    def active(self):
        print("Active discovery has not been implemented yet!")