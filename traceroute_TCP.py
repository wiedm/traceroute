# This program performs a traceroute to a destination based on opening a TCP connection
# This is done by sending TCP SYN packets
# The path is discovered by increasing the TTL and receiving ICMP TTL exceeded messages
# The program terminates when the ACK corresponding to the SYN is received




#TODO: Save the data obtained from traceroute in a datastructure


import socket
import random
import sys
import time
import struct
import os
#import plt
#import scapy.all as scapy

class Traceroute(object):


    def __init__(self, dst):
        #Destination
        self.dest_name = dst

        #Time-to-life
        self.ttl = 1
        #Number of probes which are sent per hop
        self.probes = 3
        #Set the max number of hops
        self.maxhops = 30
        #Set the timeout threshold (in ms)
        self.timeout_threshold = 5000

        #Initial TCP sequence number & source port
        self.seqnr = random.randint(0, 1000)
        self.source_port = 55000

        #Select the port which TCP tries to connect to
        #Possible improvement: Try to connect to multiple ports, everyone with a popular application
        #running on it
        self.port = 80
        print("Port: ", self.port)


    #Create an UDP sender socket
    def create_sender_socket_UDP(self):
        #create an INET, DGRAM socket
        send_socket = socket.socket(family=socket.AF_INET,
                          type=socket.SOCK_DGRAM,
                          proto=socket.IPPROTO_UDP)

        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        return send_socket


    #Create RAW TCP socket
    def create_sender_socket_TCP(self):
        #create an INET, RAW socket that runs on TCP
        send_socket = socket.socket(family=socket.AF_INET,
                          type=socket.SOCK_RAW,
                          proto=socket.IPPROTO_TCP)

        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return send_socket


    #Create a receiving ICMP RAW socket
    def create_receiver_socket(self):
        #create receiving INET, RAW socket
        recv_socket = socket.socket(family=socket.AF_INET,
                                    type=socket.SOCK_RAW,
                                    proto=socket.IPPROTO_ICMP)

        try:
            recv_socket.bind(('', self.port))
        except socket.error as err:
            raise IOError('Unable to bind receiver socket: {}'.format(err))

        return recv_socket


    #Calculates the checksum
    def checksum(self, msg):
        check = 0
        for i in range(0, len(msg), 2):
            temp = (msg[i] << 8) + (msg[i+1])
            check = check + temp

        check = (check >> 16) + (check & 0xffff)
        check = ~check & 0xffff
        return check


    #Create the TCP packet & pack it into an IP packet
    #This method is not needed for the final implementation but for testing purposes
    #Later there is a TCP packet passed & therefore does not need to be formed
    def form_tcp_packet(self, dst_IP):
        #Create an empty packet
        packet = ''

        #Get the destination and the local ip address
        try:
            #src_IP = '192.168.1.119'

            #Get local IP address by opening a UDP socket and obtaining its IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 0))
            src_IP = s.getsockname()[0]

            #dst_IP = socket.gethostbyname(self.dest_name)
            #print("src_IP: ", src_IP, "dst_IP: ", dst_IP)
        except socket.error as err:
            raise IOError('Unable to resolve {}: {}', self.dest_name, err)


        #Define the IP header fields
        ihl = 5
        version = 4
        tos = 0
        tot_len = 20 + 20
        id = random.randint(20000, 60000)
        fragment_offset = 0
        ttl = self.ttl
        protocol = socket.IPPROTO_TCP
        check = 1
        src_addr = socket.inet_aton(src_IP)
        dst_addr = socket.inet_aton(dst_IP)
        ihl_version = (version << 4) + ihl

        #Create the IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ihl_version,
                                tos,
                                tot_len,
                                id,
                                fragment_offset,
                                ttl,
                                protocol,
                                check,
                                src_addr,
                                dst_addr)

        #Define the TCP header fields
        source_port = self.source_port
        dest_port = self.port
        seq = self.seqnr
        ack_seq = 0
        doff = 5
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = 8192
        #window = socket.htons(5840)
        check = 0
        urg_ptr = 0

        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + ( ack << 4) + (urg << 5)

        #Create the TCP header
        tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window,
                                 check, urg_ptr)

        #Pseudo header fields
        placeholder = 0
        tcp_length = len(tcp_header)

        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
        psh = psh + tcp_header

        #print("PSH:", psh)
        tcp_checksum = self.checksum(psh)

        #Create TCP header again, now with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window,
                                 tcp_checksum, urg_ptr)

        #Create the packet
        packet = ip_header + tcp_header

        return packet


    #Running the sender and the receiver
    def run(self):
        #Resolve domain name to ip
        try:
            dest_addr = socket.gethostbyname(self.dest_name)
        except socket.error as err:
            raise IOError('Unable to resolve {}: {}', self.dest_name, err)

        #Print the information of the traceroute which just started
        text = 'traceroute to {} ({}), {} hops max, {}ms timeout'.format(self.dest_name, dest_addr, self.maxhops,
                                                                         self.timeout_threshold)
        print(text)


        # Loop
        while True:
            #Start timer
            start_time = time.time()

            # Create ICMP receiver socket
            recv_socket_icmp = self.create_receiver_socket()


            #Create TCP sender socket & send SYN packet
            tcp_socket = self.create_sender_socket_TCP()
            packet = self.form_tcp_packet(dest_addr)
            #send_socket.sendto(packet, (dest_addr, self.port))
            #Send the packet 3 times to make sure that one copy reaches the destination
            #TODO: Adapt port number, sequence number, checksum to obtain 3 responses
            for i in range(0,2):
                tcp_socket.sendto(packet, (dest_addr, 0))


            #Initialize the current address & the corresponding host name from the received packet
            curr_addr = None
            curr_addr_tcp = None
            curr_host_name = None
            try:
                #recv_socket_icmp.settimeout(5)
                recv_socket_icmp.setblocking(0)
                #tcp_socket.settimeout(2)
                tcp_socket.setblocking(0)
                while (not (curr_addr or curr_addr_tcp)) and (round((time.time()-start_time)*1000, 2) < 2000):
                        try:
                            data, curr_addr = recv_socket_icmp.recvfrom(4048)
                        except:
                            pass
                        try:
                            tcp_data, curr_addr_tcp = tcp_socket.recvfrom(4048)
                        except:
                            pass

                end_time = time.time()
                tot_time = round((end_time-start_time)*1000, 2)
                #print("Total time: ", tot_time)
                #print('{:<4} {:<20} {:<10} {}'.format("Dest Adr: ", dest_addr, "Curr Adr: ", curr_addr[0]))

                if curr_addr:

                    # Read the ICMP header
                    pktFormatICMP = 'bbHHh'
                    # pktSizeICMP = struct.calcsize(pktFormatICMP)
                    icmp_header_raw = data[20:28]
                    # icmp_header = struct.unpack(pktFormatICMP, data[:pktSizeICMP])
                    # icmp_type, icmp_code, icmp_checksum, icmp_p_id, icmp_sequence = struct.unpack(pktFormatICMP,
                    # icmp_header_raw)
                    # print("ICMP: ", icmp_type, icmp_code)
                    icmp_header = struct.unpack(pktFormatICMP, icmp_header_raw)
                    # print("ICMP total: ", icmp_header)


                    '''
                    # Read the IP header
                    pktFormatIP = '!BBHHHBBHII'
                    pktSizeIP = struct.calcsize(pktFormatIP)
                    ip_header = struct.unpack(pktFormatIP, data[:pktSizeIP])
                    prot = ip_header[6]
                    # print("IP_Header: ", ip_header)
                    # print("Prot: ", prot)
                    '''

                    #print("Curr_adr ", curr_addr)
                    # Resolve IP to domain name
                    try:
                        curr_host_name = str(socket.gethostbyaddr(curr_addr[0])[0])
                    except socket.error as err:
                        raise IOError('Unable to resolve {}: {}', curr_addr[0], err)
                    finally:
                        if curr_host_name == None:
                            curr_host_name = curr_addr[0]

                if curr_addr_tcp:
                    '''
                    #Ethernet header legnth
                    pktSizeETH = 14

                    # Read the IP header
                    pktFormatIP = '!BBHHHBBHII'
                    pktSizeIP = struct.calcsize(pktFormatIP)
                    #print("pktIPsize: ", pktSizeIP)
                    ip_header = struct.unpack(pktFormatIP, tcp_data[:pktSizeIP])
                    prot = ip_header[6]
                    # print("IP_Header: ", ip_header)
                    # print("Prot: ", prot)


                    #Read the TCP header
                    pktFormatTCP = '!HHLLBBHHH'
                    #pktFormatTCP = '!BBBBHHII'
                    #pktFormatTCP = '!BBI4H20sIB'

                    pktSizeTCP = struct.calcsize(pktFormatTCP)
                    pktSizeTCPOffset = pktSizeETH + pktSizeIP
                    #print("Size tcp", pktSizeTCP)
                    #tcp_header_raw = tcp_data[:pktSizeTCP]
                    tcp_header_raw = tcp_data[:pktSizeTCP]

                    tcp_header = struct.unpack(pktFormatTCP, tcp_header_raw)
                    #print("TCP header: ", tcp_header)
                    #print("TCP header[]: ", tcp_header[1])
                    '''

                    #print("Curr_adr_tcp ", curr_addr_tcp)
                    # Resolve IP to domain name
                    try:
                        curr_host_name = str(socket.gethostbyaddr(curr_addr_tcp[0])[0])
                    except socket.error as err:
                        raise IOError('Unable to resolve {}: {}', curr_addr_tcp[0], err)
                    finally:
                        if curr_host_name == None:
                            curr_host_name = curr_addr_tcp[0]

            except socket.error:
                pass
            finally:
                recv_socket_icmp.close()
                tcp_socket.close()

            if curr_addr:
                #Print the info obtained from the packet
                print('{:<3} {:<4} ({}) {} ms'.format(self.ttl, str(curr_host_name), str(curr_addr[0]), tot_time))


                #Break if an ICMP port unreachable message is received
                if icmp_header[0] == 3 and icmp_header[1] == 3:
                    print("Finished traceroute, ICMP")
                    break
                if curr_addr[0] == dest_addr:
                    print("Finished traceroute, Addr")
                    break
                #Break if a timeout occurs
                if tot_time > self.timeout_threshold:
                    print("Timeout")
                    break

            elif curr_addr_tcp:
                # Print the info obtained from the packet
                print('{:<3} {:<4} ({}) {} ms'.format(self.ttl, str(curr_host_name), str(curr_addr_tcp[0]), tot_time))

                # Break if TCP SYN ACK is received
                # Then close the TCP connection
                if curr_addr_tcp and curr_addr_tcp[0] == dest_addr:
                    print("Finished traceroute TCP SYN ACK")

                    #Close connection

                    break
                #Break if a timeout occurs
                if tot_time > self.timeout_threshold:
                    print("Timeout")
                    break
            else:
                print('{:<4} *'.format(self.ttl))

            self.ttl += 1
            self.seqnr += 1
            #self.source_port += 1
            #self.port += 1
            #print("TTL = ", self.ttl)

            #Break if the max limit of hops is reached (Avoid routing loops)
            if self.ttl > self.maxhops:
                print("Finished traceroute, maxhops reached")
                break



#This is the main program
#Here an object of Traceroute is created
arg_str = ' '.join(sys.argv[1:])
print("You entered webpage: ", arg_str)
new_traceroute = Traceroute(arg_str)
new_traceroute.run()
del new_traceroute

