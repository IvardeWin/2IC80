from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether


def local_host_discovered(mac: str, ip: str):
    """
    TODO Does something when a host is discovered

        :param mac: The mac address of the discovered host
        :param ip: The ip address of the discovered host
    """
    print(f"Found host at mac {mac} and ip {ip}!")
    # TODO do smth


def filter_host(mac: str, ip: str):
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


def test():
    sniff(count=100, store=0, prn=packet_sniffed)