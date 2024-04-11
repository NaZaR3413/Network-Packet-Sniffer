from scapy.all import sniff, show_interfaces, IP, TCP, Raw
from dns import reverse_dns
from whois_info import whois_print
import whois
import time 

'''
def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        print("test 1")
        payload = packet[Raw].load.decode('utf-8', 'ignore')
        if "Host:" in payload:
            print("test 2")
            # Splits the payload on newlines and looks for the Host header
            headers = payload.split('\r\n')
            host_header = next((h for h in headers if "Host:" in h), None)
            if host_header:
                # Extracts the domain name from the Host header
                print("test 3")
                domain = host_header.split(' ')[1]
                print(f"Domain requested: {domain}")

'''
    
def packet_callback(packet):
    if packet.haslayer(IP):
        # grab ip address of source and destination
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Ignore mDNS traffic
        if packet[IP].dst == "224.0.0.251" or packet[IP].dst == "ff02::fb":
            return
        
        # attampt to grab source/destination names
        src_name = reverse_dns(src_ip)
        dst_name = reverse_dns(dst_ip)
        
        print("\n\n\npacket summary: " + packet.summary())
        print(f"Packet: {src_ip} ({src_name}) -> {dst_ip} ({dst_name})")
        
        # use whois if more information wanted
        src_who = whois.whois(src_ip) # assign whois search on source
        dst_who = whois.whois(dst_ip) # assign whois search on destination
        print("\033[92mSource: \033[0m")
        whois_print(src_who)
        print("\033[92mDestination: \033[0m")
        whois_print(dst_who)


def main():
    # Display list of available network interfaces
    #show_interfaces()

    #interface to search through 
    iface_name = "Intel(R) Wireless-AC 9462"  

    # adjust the range according to how many packets you want to sniff
    for i in range(5):
        sniff(iface=iface_name, prn=packet_callback, count=1) # Start sniffing on the specified interface

if __name__ == "__main__":
    main()
