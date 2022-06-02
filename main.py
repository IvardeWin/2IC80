from time import sleep

from scapy.arch import get_if_list

from src import discover

config = dict()
config["hosts"] = dict()


if __name__ == "__main__":
    for interface in get_if_list():
        config["hosts"][interface] = dict()
        discover.Discover(config, interface).start()
    while True:
        print(config["hosts"])
        sleep(10)
