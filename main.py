from time import sleep

from scapy.arch import get_if_list

from src import discover

hosts = dict()

if __name__ == "__main__":
    for interface in get_if_list():
        hosts[interface] = dict()
        disc = discover.Discover(hosts, interface)
        disc.start()
        disc.active()
    while True:
        print(hosts)
        sleep(10)
