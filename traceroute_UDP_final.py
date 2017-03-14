# This program performs a traceroute to a webpage based on sending UDP packets with
# increasing TTL to trigger ICMP Time to Life Exceeded messages as a response
# The port which UDP tries to connect to is chosen such that there should be no
# application listening on this port. The termination condition therefore is an ICMP Port Unreachable
# message or a timeout.


import socket
import random
import sys
import time
import struct


class Traceroute(object):

    #Initialize some variables
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

        #Select a random port
        self.port_base = 33434
        self.port_max = self.port_base + self.maxhops + (self.ttl*self.probes-1)
        self.port = random.randint(self.port_base, self.port_max)
        print("Port: ", self.port)
        #print("Initialization done!")

    #This function returns a UDP sender socket
    def create_sender_socket(self):
        #create an INET, DGRAM socket
        send_socket = socket.socket(family=socket.AF_INET,
                          type=socket.SOCK_DGRAM,
                          proto=socket.IPPROTO_UDP)

        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        return send_socket

    #This function returns a RAW socket which is capturing ICMP packets
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


    #This function does the sending and reception of packets
    def run(self):
        #Resolve domain name to ip
        try:
            dest_addr = socket.gethostbyname(self.dest_name)
        except socket.error as err:
            raise IOError('Unable to resolve {}: {}', self.dest_name, err)

        #Print the information of the traceroute which just started
        text = 'traceroute to {} ({}), {} hops max, {}ms timeout'.format(self.dest_name, dest_addr, self.maxhops, self.timeout_threshold)
        print(text)


        # Loop
        while True:
            #Start timer
            start_time = time.time()

            # Create sender and receiver socket
            recv_socket = self.create_receiver_socket()

            #Create UDP sender socket
            send_socket = self.create_sender_socket()
            send_socket.sendto(b'', (self.dest_name, self.port))


            #Initialize the current address & the corresponding host name from the received packet
            curr_addr = None
            curr_host_name = None
            try:
                recv_socket.settimeout(5)
                data, curr_addr = recv_socket.recvfrom(4048)
                #print("After recvfrom")

                end_time = time.time()
                tot_time = round((end_time-start_time)*1000, 2)
                #print("Total time: ", tot_time)
                #print('{:<4} {:<20} {:<10} {}'.format("Dest Adr: ", dest_addr, "Curr Adr: ", curr_addr[0]))


                #Read the ICMP header
                pktFormatICMP = 'bbHHh'
                icmp_header_raw = data[20:28]
                icmp_header = struct.unpack(pktFormatICMP, icmp_header_raw)
                #print("ICMP total: ", icmp_header)


                '''
                #Read the IP header
                pktFormatIP = '!BBHHHBBHII'
                pktSizeIP = struct.calcsize(pktFormatIP)
                ip_header = struct.unpack(pktFormatIP, data[:pktSizeIP])
                prot = ip_header[6]
                print("IP_Header: ", ip_header)
                print("Prot: ", prot)
                '''

                #Resolve IP to domain name
                try:
                    curr_host_name = str(socket.gethostbyaddr(curr_addr[0])[0])
                except socket.error as err:
                    raise IOError('Unable to resolve {}: {}', curr_addr[0], err)
                finally:
                    if curr_host_name == None:
                        curr_host_name = curr_addr[0]

            except socket.error:
                pass
            finally:
                recv_socket.close()
                send_socket.close()

            if curr_addr:
                print('{:<3} {:<4} ({}) {} ms'.format(self.ttl, str(curr_host_name), str(curr_addr[0]), tot_time))

                #Break if an ICMP port unreachable message is received
                if icmp_header[0] == 3 and icmp_header[1] == 3:
                    print("Finished traceroute")
                    break
                #Break if a timeout occurs
                if tot_time > self.timeout_threshold:
                    print("Timeout")
                    break
            else:
                print('{:<4} *'.format(self.ttl))

            self.ttl += 1
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

