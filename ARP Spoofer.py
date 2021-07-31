ascii_banner = pyfiglet.figlet_format("ARP Spoofer")
print(ascii_banner)

import pyfiglet

import scapy.all as scapy
  
  
# code to get MAC Address
def mac(ipadd):
  # requesting arp packets from the IP address
  # if it's wrong then will throw error
    arp_request = scapy.ARP(pdst=ipadd)
    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = scapy.srp(arp_req_br, timeout=5,
                       verbose=False)[0]
    return list_1[0][1].hwsrc
  
# taking interface of the system as an argument
# to sniff packets inside the network
def sniff(interface):
    # store=False tells sniff() function 
    # to discard sniffed packets
    scapy.sniff(iface=interface, store=False, 
                prn=process_sniffed_packet)
  
  
# defining function to process sniffed packet
def process_sniffed_packet(packet):
  # if it is an ARP packet and if it is an ARP Response
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
  
       # originalmac will get old MAC whereas
        originalmac = mac(packet[scapy.ARP].psrc)
        # responsemac will get response of the MAC
        responsemac = packet[scapy.ARP].hwsrc
  
  
# machine interface is "eth0", sniffing the interface
sniff("eth0")