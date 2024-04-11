import whois

def whois_print(src):
    # do not try to combine any prints. Errors resonating on the whois side
    print("Domain_name:")
    print(src.domain_name)
    
    print("\nRegistrar:")
    print(src.registrar)
    
    print("\nwhois_server")
    print(src.whois_server)

    print("\nemails:")
    print(src.emails)
    
    print("\ncity:")
    print(src.city)
    
    print("\nstate:")
    print(src.state)