#!/usr/bin/python3.3
#Sniffs only incoming TCP packet

import socket, sys
import struct

#create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)
    #packet string from tuple
    packet = packet[0]

    #take first 20 characters for the ip header
    ip_header = packet[0:20]

    #now unpack them :)
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
   
    version_ihl = iph[0]
    version = version_ihl >> 4

    #	                        0000 0000 0000 0000 0000 0100 0101
    #       0xF signfifica      0000 0000 0000 0000 0000 0000 1111
    #                          ======================================= (AND)
    #                           0000 0000 0000 0000 0000 0000 0101  =>(5 HEXADECIMAL)

    ihl = version_ihl & 0xF



    iph_length = ihl * 4

    
    ip_tos = iph[1] # char
    ip_len = iph[2] # short int
    ip_id = iph[3]  # short int
    ip_off = iph[4] # short int
    #------------------
    ip_ttl = iph[5] #char
    ip_p = iph[6]   #char
    ip_sum = iph[7] #shor int

    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    print("\tIP Header")
    print('IP Version : ' + str(version) )
    print('IP Header Length (IHL) : ' , ihl, 'DWORDS or',str(ihl*32//8) ,'bytes')
    print('Type of Service (TOS): ',str(ip_tos))
    print('IP Total Length: ',ip_len, ' DWORDS ',str(ip_len*32//8) ,'bytes')
    print('Identification: ',ip_id)
    print('flags: ',ip_off)
    
    print('TTL : ' + str(ip_ttl))
    print('Protocol : ' + str(ip_p) )
    print('Chksum: ',ip_sum)
    print('Source Address IP : ' + str(s_addr) )
    print('Destination Address IP: ' + str(d_addr))
    print("")

    tcp_header = packet[iph_length:iph_length+20]

    #now unpack them :)
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)






    source_port = tcph[0]   # uint16_t
    dest_port = tcph[1]     # uint16_t
    sequence = tcph[2]      # uint32_t
    acknowledgement = tcph[3]   # uint32_t
    doff_reserved = tcph[4]     # uint8_t
    tcph_length = doff_reserved >> 4

    tcph_flags = tcph[5]            #uint8_t
    tcph_window_size = tcph[6]      #uint16_t
    tcph_checksum = tcph[7]         #uint16_t
    tcph_urgent_pointer = tcph[8]   #uint16_t
    
    print("\tTCP Header")
    
    print("Source Port:",source_port)
    print("Destination Port:",dest_port)
    print("Sequence Number:",sequence)
    print("Acknowledge Number:",acknowledgement)
    print("Header Length:",tcph_length,'DWORDS or ',str(tcph_length*32//8) ,'bytes')

    print("Urgent Flag:",tcph_flags)

    print("Acknowledgement Flag:")
    print("Push Flag:")
    print("Reset Flag:")
    print("Synchronise Flag:")
    print("Finish Flag:")

    print("Window Size:",tcph_window_size)
    print("Checksum:",tcph_checksum)
    print("Urgent Pointer:",tcph_urgent_pointer)
    print("")

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    #get data from the packet
    data = packet[h_size:]

    print ('Data : ' + str(data))
    print ()
