"""
Assignment for course 2IC80, Lab on Offensive Computer Security, at TU/e
Created by;
Daan Boelhouwers(1457152), d.boelhouwers@student.tue.nl
Richard Farla(1420380), r.farla@student.tue.nl
Ivar de Win(1406663), i.j.f.d.win@student.tue.nl
"""

from scapy import packet
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff
import threading


class Discover(threading.Thread):

    def __init__(self, hosts: dict, interface: str):
        """
        Discovers other hosts in the local network in a background thread

            :param hosts: The configuration dictionary that stores all discovered hosts
            :param interface: The interface on which this thread operates
        """
        super(Discover, self).__init__()
        self.hosts = hosts
        self.interface = interface
        self._stop = threading.Event()

    def stop(self):
        """
        Stops the background thread
        """
        self._stop.set()

    def is_stopped(self):
        """
        Returns whether this thread has been stopped
        """
        return self._stop.isSet()

    def run(self):
        """
        Starts the background thread
        """

        def local_host_discovered(mac: str, ip: str):
            """
            Add found host to the dictionary

                :param mac: The mac address of the discovered host
                :param ip: The ip address of the discovered host
            """
            iface_hosts = self.hosts[self.interface]
            if mac not in iface_hosts:
                iface_hosts.update(dict({mac: [ip]}))
                print(
                    f"New host discovered on {self.interface}, MAC: {mac} IP: {ip}")
            elif ip not in iface_hosts[mac]:
                iface_hosts[mac].append(ip)
                print(
                    f"New IP discovered on {self.interface} for host with MAC: {mac}, IP: {ip}")

        def filter_host(mac: str, ip: str):
            """
            Filters out all unwanted hosts

            Args:
                :param mac: The mac address of a host 
                :param ip: The ip address of a host
            """
            # Filter out broadcasts
            if mac == "ff:ff:ff:ff:ff:ff":
                return
            # Filter out self
            if mac == get_if_hwaddr(self.interface):
                return
            if ip == get_if_addr(self.interface):
                return
            local_host_discovered(mac, ip)

        def packet_sniffed(pkt: packet):
            """
            Retrieves the mac- and ip-address of hosts from sniffed packets

                :param pkt: The sniffed packet
            """
            if IP in pkt:
                filter_host(pkt[Ether].src, pkt[IP].src)
                filter_host(pkt[Ether].dst, pkt[IP].dst)
            if ARP in pkt:
                filter_host(pkt[Ether].src, pkt[ARP].psrc)
                filter_host(pkt[Ether].dst, pkt[ARP].pdst)

        # Attempt to sniff for packets on the current interface
        while not self.is_stopped():
            try:
                sniff(iface=self.interface, store=0,
                      timeout=1, prn=packet_sniffed)
            except IndexError:
                print(f"Layer not found")
                self.stop()
            except OSError:
                print(
                    f"Could not open the adapter for interface {self.interface}")
                self.stop()
            except Scapy_Exception:
                print(f"Could not operate on interface {self.interface}")
                self.stop()
