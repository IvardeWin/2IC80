from time import sleep

from scapy.arch import get_if_list
from netifaces import interfaces, ifaddresses, AF_INET

from src import discover

hosts = dict()


if __name__ == "__main__":
    #for interface in get_if_list():
    #    hosts[interface] = dict()
    #    discover.Discover(hosts, interface).start()
    #while True:
    #    print(hosts)
    #    sleep(10)
    for iface in interfaces():
        print (ifaddresses(iface))
