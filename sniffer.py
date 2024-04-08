from scapy.all import sniff, show_interfaces

def packet_callback(packet):
    print(packet.summary())

def main():
    # Display list of available network interfaces
    show_interfaces()

    #interface to search through 
    iface_name = "Intel(R) Wireless-AC 9462"  

    # Start sniffing on the specified interface
    sniff(iface=iface_name, prn=packet_callback, count=10)

if __name__ == "__main__":
    main()
