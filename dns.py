import socket

def reverse_dns(ip_addr):
    try: # try to grab the host addr from imported ip
        return socket.gethostbyaddr(ip_addr)[0]
    except socket.herror: # unable to resolve
        return None