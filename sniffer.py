from scapy.all import sniff, show_interfaces, IP
from dns import reverse_dns
import whois

def packet_callback(packet):
    if packet.haslayer(IP):
        # grab ip address of source and destination
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        
        # Ignore mDNS traffic
        if packet[IP].dst == "224.0.0.251" or packet[IP].dst == "ff02::fb":
            return
        
        # attampt to grab source/destination names
        src_name = reverse_dns(src_ip)
        dst_name = reverse_dns(dest_ip)
        
        print("\n\n\npacket summary: " + packet.summary())
        print(f"Packet: {src_ip} ({src_name}) -> {dest_ip} ({dst_name})")
        
        # use whois if more information wanted
        #src_who = whois.whois(src_ip) # assign whois search on source
        #dst_who = whois.whois(dst_ip) # assign whois search on destination
        #print(src_who) 
        #print(dst_who) 
        

def main():
    # Display list of available network interfaces
    #show_interfaces()

    #interface to search through 
    iface_name = "Intel(R) Wireless-AC 9462"  

    # adjust the range according to how many packets you want to sniff
    for i in range(20):
        sniff(iface=iface_name, prn=packet_callback, count=1) # Start sniffing on the specified interface

if __name__ == "__main__":
    main()
