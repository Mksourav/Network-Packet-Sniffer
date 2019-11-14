'''

Sniff packets and return a list of packets.



Arguments:



  count: number of packets to capture. 0 means infinity.



  store: whether to store sniffed packets or discard them



  prn: function to apply to each packet. If something is returned, it

      is displayed.



      Ex: prn = lambda x: x.summary()



  filter: BPF filter to apply.



  lfilter: Python function applied to each packet to determine if

      further action may be done.



      Ex: lfilter = lambda x: x.haslayer(Padding)



  offline: PCAP file (or list of PCAP files) to read packets from,

      instead of sniffing them



  timeout: stop sniffing after a given time (default: None).



  L2socket: use the provided L2socket (default: use conf.L2listen).



  opened_socket: provide an object (or a list of objects) ready to use

      .recv() on.



  stop_filter: Python function applied to each packet to determine if

      we have to stop the capture after this packet.



      Ex: stop_filter = lambda x: x.haslayer(TCP)



  iface: interface or list of interfaces (default: None for sniffing

      on all interfaces).



The iface, offline and opened_socket parameters can be either an

element, a list of elements, or a dict object mapping an element to a

label (see examples below).



Examples:



  >>> sniff(filter="arp")



  >>> sniff(lfilter=lambda pkt: ARP in pkt)



  >>> sniff(iface="enp0s8", prn=Packet.summary)



  >>> sniff(iface=["enp0s8", "mon0"],

  ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,

  ...                                   pkt.summary()))



  >>> sniff(iface={"enp0s8": "Ethernet", "mon0": "Wifi"},

  ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,

  ...                                   pkt.summary()))

'''





#Importing the necessary modules

import logging

from datetime import datetime

import subprocess

import sys

from tkinter import *

import tkinter.ttk as ttk

from tkinter.ttk import Notebook



#This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

logging.getLogger("scapy.loading").setLevel(logging.ERROR)





try:

    from scapy.all import *



except ImportError:

    print("Scapy package for Python is not installed on your system.")

    sys.exit()





#Printing a message to the user; always use "sudo scapy" in Linux!

print("\n! Make sure to run this program as ROOT !\n")





#Asking the user for some parameters: interface on which to sniff, the number of packets to sniff, the time interval to sniff, the protocol



#Asking the user for input - the interface on which to run the sniffer

net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")



#Setting network interface in promiscuous mode

'''

Wikipedia: In computer networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network interface controller (NIC) or wireless network interface controller (WNIC) that causes the controller to pass all traffic it receives to the central processing unit (CPU) rather than passing only the frames that the controller is intended to receive.

This mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub.

'''

try:

    subprocess.call(["ifconfig", net_iface, "promisc"], stdout = None, stderr = None, shell = False)



except:

    print("\nWARNING! Failed to configure interface as promiscuous.\n")



else:

    #Executed if the try clause does not raise an exception

    print("\n=>Interface %s was set to PROMISC mode!\n" % net_iface)





#Asking the user for the number of packets to sniff (the "count" parameter)

pkt_to_sniff = input("\n* Enter the number of packets to capture (0 is infinity): ")



#Considering the case when the user enters 0 (infinity)

if int(pkt_to_sniff) != 0:

    print("\n=>The program will capture %d packets!\n" % int(pkt_to_sniff))



elif int(pkt_to_sniff) == 0:

    print("\n=>The program will capture packets until the timeout!\n")





#Asking the user for the time interval to sniff (the "timeout" parameter)

time_to_sniff = input("\n* Enter the number of seconds to run the capture: ")



#Handling the value entered by the user

if int(time_to_sniff) != 0:

    print("\n=>The program will capture packets for %d seconds!\n" % int(time_to_sniff))





#Asking the user for any protocol filter he might want to apply to the sniffing process

#For this example I chose three protocols: ARP, ICMP

#You can customize this to add your own desired protocols

proto_sniff = input("\n* Enter the protocol to filter by (arp || icmp || 0 is all): ")



#Considering the case when the user enters 0 (meaning all protocols)

if (proto_sniff == "arp") or (proto_sniff == "icmp"):

    print("\n=>The program will capture only %s packets!\n" % proto_sniff.upper())



elif (proto_sniff) == "0":

    print("\n=>The program will capture all protocols!\n")





#Asking the user to enter the name and path of the log file to be created

file_name = input("\n* Please give a name to the log file: ")



#Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending

sniffer_log = open(file_name, "a")





#This is the function that will be called for each captured packet

#The function will extract parameters from the packet and then log each packet to the log file

def packet_log(packet):



    #Getting the current timestamp

    now = datetime.now()



    #Writing the packet information to the log file, also considering the protocol or 0 for all protocols

    if proto_sniff == "0":

        #Writing the data to the log file

        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)



    elif (proto_sniff == "arp") or (proto_sniff == "icmp"):

        #Writing the data to the log file

        print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)





#Printing an informational message to the screen

print("\n* Starting the capture...")





#Running the sniffing process (with or without a filter)

if proto_sniff == "0":

    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)



elif (proto_sniff == "arp") or (proto_sniff == "icmp"):

    sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)



else:

    print("\nWARNING! Could not identify the protocol.\n")

    sys.exit()



#Printing the closing message

print("\n* Displaying the captured packets saved in %s.\n" % file_name)





#Closing the log file

sniffer_log.close()





#subprocess.call(" python3 disp.py 1", shell=True)







#Displaying the captured packets information through GUI mode

container=Tk()



container.title('Network Packet Sniffer')

container.geometry('800x600')

generalites=Frame(container,bg='powder blue')

generalites.pack(side=BOTTOM)



s_generalites= Scrollbar(generalites)

T_generalites= Text(generalites,bg='powder blue',width=350,height=350)



s_generalites.pack(side=RIGHT, fill=Y)

T_generalites.pack(side=LEFT, fill=Y)

s_generalites.config(command=T_generalites.yview)

T_generalites.config(yscrollcommand=s_generalites.set)



filename =(file_name)

fichier = open(filename, "r")

content_generalites= fichier.read()

fichier.close()



T_generalites.insert(END, content_generalites)



container.mainloop()



print("Thank you for using the service!")



#End of the program. 
