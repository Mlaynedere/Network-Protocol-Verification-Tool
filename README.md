# Network-Protocol-Verification-Tool

<p align="center">
  <img src="https://img.shields.io/badge/language-python-blue.svg">
  <img src="https://img.shields.io/badge/library-Scapy-green.svg">
  <img src="https://img.shields.io/badge/library-Socket-yellow.svg">
  <img src="https://img.shields.io/badge/library-SSL-orange.svg">
  <img src="https://img.shields.io/badge/library-Time-lightgrey.svg">
  <img src="https://img.shields.io/badge/library-Threading-blueviolet.svg">
  <img src="https://img.shields.io/badge/library-PyBGPStream-brightgreen.svg">
  <img src="https://img.shields.io/badge/library-pytz-lightblue.svg">
</p>

A multi-purpose network management tool written in Python that checks network protocols and tests the netowrk's security using several libraries. The script analyzes BGP used in the netowrk infrastructure and checks for TLS and IPsec. In addition, this tool simulates an ARP spoofing attack to test the robustness of the netowrk at its 2nd layer. This tool is **strictly for educational purposes** and should not be used for malicious activities.

## Project Overview

### **IPsec**
  - Function to make sure packets are sent from the device using IPsec protocol
  - Validates IP header
  - Checks for protocol number
  - Protocol number 50 for IPsec ESP
  - Protocol number 51 for IPsec AH
  - Protocol number 6 for TCP
  - Protocol number 17 for UDP

### **TLS**
  - Function to check if packets sent from the device are using TLS protocol
  - Takes a URL as input and validates the website URL format
  - Checks for HTTPS support
  - Checks for HSTS (HTTPS Strict-Transport-Security) in https header
  - Create a custom SSL context to get SSL/TLS information
  - Prints specifications of TLS used

### **ARP Spoof Attack**
  - Function to simulate a arp-spoof man in the middle attack to check if the network is vulnerable
  - Utilize Scapy's ping function to discover devices on the netowrk
  - Get the MAC and IP address of the gateway with the help of get_gateway_mac_address function
  - Maintain internet connection on the target through IP forwarding
  - Update the ARP tables
  - Send a fake packet saying that we're at the router's IP to the target machine
  - Send a packet to the router that we are at the target machine's IP
  - Sniff packets on the network and writes it to a pcap file

### **BGP Analysis**
  - Function to check the safety of the BGP used
  - Obtain ISP name
  - Utilize "Is BGP Safe Yet?" to check if ISP is safe
  - Initialize a stream using PyBGPStream
  - Extract specific details of the ISP such as time-stamp, routes, origin and many more
  - Analyze the BGP of the ISP


## Usage
To run the tool, a parameter should be specified
Watch the demo under this link: https://www.youtube.com/watch?v=3pBf9pOxO-o
