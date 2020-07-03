#Realizado por Luis Hector Huanca Rosas

import socket
from struct import *
import datetime
import pcapy
import sys

print ('-------Sniffer Python-------')
print ('Luis Hector Huanca Rosas\t\tCI: 4848216 LP')
print('Paralelo A Lic Gallardo\t\tJueves 16:00 - 18:00')


def main(argv):
    #list all devices
    devices = pcapy.findalldevs()
    print (devices)

    #ask user to enter device name to sniff
    print ("Las interfaces disponibles son :")
    for d in devices :
        print (d)

    dev = raw_input("Enter device name to sniff : ")

    print ("Sniffing device " + dev)

    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live(dev , 65536 , 1 , 0)

    #start sniffing packets
    while(1) :
        (header, packet) = cap.next()
        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

#function to parse a packet
def parse_packet(packet) :

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print('Ethernet Header')
    print("\t|-Destination MAC : " + eth_addr(packet[0:6]))
    print("\t|-Source MAC      : " + eth_addr(packet[6:12]))
    print("\t|-Protocol        : " + str(eth_protocol))

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        #Estructura de la IP Header
        ip_tos = iph[1]
        ip_len = iph[2]
        ip_id = iph[3]
        ip_off = iph[4]
        #--------------------------------
        ttl = iph[5]
        protocol = iph[6]
        ip_sum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print("\nIP Header")
        print("\t|-IP Version       : " + str(version))
        print("\t|-IP Header Length : " + str(ihl) + "DWORDS or " + str(ihl*32//8) + "bytes")
        print("\t|-Type of Service  : " + str(ip_tos))
        print("\t|-IP total length  : " + str(ip_len*32//8) + " Bytes (Size of Packet)")
        print("\t|-Identification   : " + str(ip_id))
        print("\t|-TTL              : " + str(ttl))
        print("\t|-Protocol         : " + str(protocol))
        print("\t|-Checksum         : " + str(ip_sum))
        print("\t|-Source IP        : " + str(s_addr))
        print("\t|-Destination IP   : " + str(d_addr))

        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            tcph_flags = tcph[5]
            tcph_window_size = tcph[6]
            tcph_checksum = tcph[7]
            tcph_urgent_pointer = tcph[8]
            binario = '{0:b}'.format(tcph_flags)
            #while binario.lenght < 5:
            #    binario = "0" + binario

            print('\nTCP Header')
            print("\t|-Source Port          : " + str(source_port))
            print("\t|-Destination Port     : " + str(dest_port))
            print("\t|-Sequence Number      : " + str(sequence))
            print("\t|-Acknowledge Number   : " + str(acknowledgement))
            print("\t|-Header lenght        : " + str(tcph_length) + " DWORDS or " + str(tcph_length*32//8) + "bytes")
            print("\t|-Urgent Flag          : " + str(tcph_flags))
            print("\t|-Acknowledgement Flag : " + str(binario[0]))
            print("\t|-Push Flag            : " + str(binario[1]))
            print("\t|-Reset Flag           : " + str(binario[2]))
            print("\t|-Synchronise Flag     : " + str(binario[3]))
            print("\t|-Finish Flag          : " + str(binario[4]))
            print("\t|-Windows              : " + str(tcph_window_size))
            print("\t|-Checksum             : " + str(tcph_checksum))
            print("\t|-Urgent Pointer       : " + str(tcph_urgent_pointer))

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print ('Data : ' + data)

        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            
            print('\nICMP Header')
            print("\t|-Type       : " + str(icmp_type))
            print("\t|-Code       : " + str(code))
            print("\t|-Checksum   : " + str(checksum))

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print ('Data : ' + data)

        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print('\nUDP Header')
            print("\tSource Port : " + str(source_port))
            print("\tDest Port   : " + str(dest_port))
            print("\tLength      : " + str(length))
            print("\tChecksum    : " + str(checksum))

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print ('Data : ' + data)

        #some other IP packet like IGMP
        else :
            print ('Protocol other than TCP/UDP/ICMP')

        print ()

if __name__ == "__main__":
  main(sys.argv) 