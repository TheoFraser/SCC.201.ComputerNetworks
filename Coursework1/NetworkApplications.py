#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        try:
            rec_packet, addr = icmpSocket.recvfrom(1024)
        except socket.timeout:
            print("An execption occured")
            return "ERR","ERR"
        icmp_header = rec_packet[20:28]
        type,code,checksum,id,seq_number = struct.unpack('bbHHh', icmp_header)
        if id == ID:
            time_recieved = time.time()
            ttl = rec_packet[8]
            return time_recieved, ttl
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        ICMP_ECHO = 8
        seq_number = 1
        header = struct.pack(
			"bbHHh", ICMP_ECHO, 0, 0, ID, 0
		)
        cheksum = self.checksum(header)
        header = struct.pack(
			"bbHHh", ICMP_ECHO, 0, cheksum, ID, 0
		)
        icmpSocket.sendto(header,(destinationAddress,1))
        time_send = time.time()
        return time_send
        # 1. Build ICMP header
        # 2. Checksum ICMP packet using given function
        # 3. Insert checksum into packet
        # 4. Send packet using socket
        # 5. Record time of sending
        pass

    def doOnePing(self, destinationAddress, timeout):
        ID = random.randint(0,50)
        imcpS = socket.socket(
            family = socket.AF_INET,
            type = socket.SOCK_RAW,
            proto = socket.IPPROTO_ICMP
        )
        imcpS.settimeout(timeout)
        sent = self.sendOnePing(imcpS, destinationAddress,ID)
        recieved,ttl = self.receiveOnePing(imcpS,destinationAddress,ID,2)
        imcpS.close
        if(recieved == "ERR"):
            return recieved,ttl
        delay = (recieved*1000) - (sent*1000)
        return delay,ttl
        # 1. Create ICMP socket
        # 2. Call sendOnePing function
        # 3. Call receiveOnePing function
        # 4. Close ICMP socket
        # 5. Return total network delay
        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        hostnameIP = socket.gethostbyname(args.hostname)
        print(f'The {args.hostname} IP Address is {hostnameIP}')
        for x in range(6):
            delay,ttl = self.doOnePing(hostnameIP,5)
            if delay == "ERR":
                print("Timeout")
            else:
                self.printOneResult(hostnameIP,struct.calcsize("bbHHh"),delay,ttl)
            time.sleep(1)
        
        # 1. Look up hostname, resolving it to an IP address
        # 2. Call doOnePing function, approximately every second
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
        # self.printOneResult('1.1.1.1', 50, 20.0, 150) # Example use of printOneResult - complete as appropriate
        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):
    def sendOneTraceroute(self, dest_addr, timeout):
        port = 33434
        ttl = 1
        cur_addr = None
        while cur_addr != dest_addr:
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            imcpS = socket.socket(
                family = socket.AF_INET,
                type = socket.SOCK_RAW,
                proto = socket.IPPROTO_ICMP
            )
            imcpS.settimeout(timeout)
            tx.sendto("lol".encode(),(dest_addr, port))
            try:
                rec_packet, addr = imcpS.recvfrom(1024)
                cur_addr = addr[0]
                self.printOneResult(cur_addr,struct.calcsize("bbHHh"),200,ttl)
            except socket.timeout:
                print("TimeOut")
            except socket.error:
                print("An execption occured")
                print(cur_addr)
            ttl = ttl + 1
            tx.close()
            imcpS.close()
        pass
    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))
        hostNameIP = socket.gethostbyname(args.hostname)
        print(f'The {args.hostname} IP Address is {hostNameIP}')
        self.sendOneTraceroute(hostNameIP,5)
    
    
class ParisTraceroute(NetworkApplication):
    def receiveParisTraceroute(self,send_socket):
        try:
            rec_packet, addr = send_socket.recvfrom(1024)                                           #the socket will receive a packet and a address 
            time_recieved = time.time()                                                             #time recieved is equal to the time at that specific time
            cur_addr = addr[0]                                                                      #gets the current address for the address
            icmp_header = rec_packet[20:28]                                                         #gets the specific icmp header from the recieved packet
            type,code,checksum,id,seq_number = struct.unpack('bbHHh', icmp_header)                  #unpacks the icmp header into its type, code, checksum, id, sequence number (signed char, signed char, unsigned short, unsigned short, short)
            cur_name,__,__ = socket.gethostbyaddr(cur_addr)                                         #gets the current name of the router based on it current address                                          
            return cur_addr, cur_name, time_recieved, type, code                                    #returns current address, current name, time recieved, type and code
        except socket.timeout:                                                                      #if there is a timeout it will return None, None, None, None and None
            return None, None, None, None, None
        except socket.error:                                                                        #if current address doesn't have a current name then it will return the current address, current address, time recieved, type and code
            return cur_addr, cur_addr, time_recieved, type, code
        except:
            exit()
        pass
    def sendParisTraceroute(self,dest_addr, port,send_socket):
        if(args.protocol == 'icmp'):
            #if the protocol is icmp then create a icmp echo packet with same ID and sequenceNumber so the checksum is the same for each packet
            ICMP_ECHO = 8
            seq_number = 1
            ID = 0
            header = struct.pack(
                "bbHHh", ICMP_ECHO, 0, 0, ID, 0
            )
            cheksum = self.checksum(header)
            header = struct.pack(
                "bbHHh", ICMP_ECHO, 0, cheksum, ID, 0
            )                                                                
            send_socket.sendto(header,(dest_addr, 1))                                                   #sends the icmp echo packets to the destination address
        if(args.protocol == 'udp'):
            #if the protocol is udp it will send a udp packet to the destination address down the port specified which is the same for every udp packet 
            send_socket.sendto("LOL".encode() ,(dest_addr,port))
        time_send = time.time()                                                                         #time sent is equal to the time at that specific time
        return time_send
        pass
    def doOneParisTraceroute(self,dest_addr, ttl, port,send_socket):
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)                                       #sets the ttl of the socket 
        time_sent = self.sendParisTraceroute(dest_addr, port, send_socket)                              #calls sendParisTraceroute and it returns time_sent
        if(args.protocol == "udp"):                                                                     
            #if the protocol is icmp it will create a icmp socket and set a timeout and then call receiveOneParisTraceroute which returns current address, current Name, time_recieved, type, code
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.settimeout(args.timeout)
            cur_addr, cur_name, time_recieved, type, code = self.receiveParisTraceroute(icmp_socket)
        if(args.protocol == "icmp"):
            #if the protocol is icmp then call receiveOneParisTraceroute which returns current address, current Name, time_recieved, type, code
            cur_addr, cur_name, time_recieved, type, code = self.receiveParisTraceroute(send_socket)
        if(cur_addr != None):
            #if current address is not NONE then return current address, current Name, delay, type and code
            return cur_addr, cur_name, ((time_recieved - time_sent) * 1000), type, code 
        #if current address is NONE then return current address, current Name, time_recieved, type and code
        return cur_addr, cur_name, time_recieved, type, code
        pass
    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Paris-Traceroute to: %s...' % (args.hostname))
        hostNameIP = socket.gethostbyname(args.hostname)
        print(f'The {args.hostname} IP Address is {hostNameIP}, Protocol is {args.protocol}')
        port = 33434                                                                                #holds the port number
        ttl = 1                                                                                     #sets the ttl to 1 as we want the first hop to go to the first router
        cur_addr = [None, None, None]                                                               #creates a list for current address
        cur_name = [None, None, None]                                                               #creates a list for current name
        delay = [None, None, None]                                                                  #creates a list for delay
        exit = 0                                                                                                                                                                       
        type = None                                                                                 
        code = None
        all_delay = []                                                                             #creates a empty list for all the delays                                 
        total_packets = 0                                                                          #this variable stores the total amount of packets sent
        timeout_packets = 0                                                                        #this variable stores the packets that timeout
        if(args.protocol == "udp"):                                                                #if the protocol is udp will create a udp socket
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if(args.protocol == "icmp"):
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)      #if the protocol is icmp will create a icmp socket
            send_socket.settimeout(args.timeout)
        while type !=0 and exit != 3 and (type != 3 and code !=3):                                 
            #while exit is not 3 (the number of times in a row that all packets timeout on a specific router) or type is not 0 (means destination has been reached) or type and code is 3 (means destination port is unreachable)
            for x in range(3):
                cur_addr[x-1], cur_name[x-1], delay[x-1], type, code = self.doOneParisTraceroute(hostNameIP, ttl, port, send_socket)    #calls doOneParisTraceroute and it returns current address, current Name, delay, type and code
                if(delay[x-1] == None):                                                            #if delay is None timeout_packets is increased
                    timeout_packets = timeout_packets + 1
                else:
                    all_delay.append(delay[x-1])                                                   #if delay is not None add the delay to the list of total delays
                total_packets = total_packets + 1                                                  #increases packets send by 1
            if(delay == [None,None,None]):                                                         #if all packets timeout on the same router increase exit count by 1
                exit = exit + 1
            else:
                for i in range(3):
                    if(cur_addr[i-1] != None):                                                     #this gets the value that isn't NONE in current Name and current address and makes actual address and actual Name equal to it 
                        actual_addr = cur_addr[i-1]
                        actual_name = cur_name[i-1]
                        if(cur_addr[i-1] == cur_name[i-1]):
                            actual_name = cur_addr[i-1]
                exit = 0                                                                           #sets exit to 0
            self.printMultipleResults(ttl,actual_addr,delay,actual_name)                          
            ttl = ttl + 1                                                                          #increases ttl by 1
        self.printAdditionalDetails((timeout_packets/total_packets *100), min(all_delay), sum(all_delay)/len(all_delay), max(all_delay))        #once the paris-traceroute is done or timeouts it will print the additional details
        send_socket.close()                                                                        #closes the socket


class WebServer(NetworkApplication):

    def handleRequest(self ,tcpSocket):
        file = ''
        message = tcpSocket.recv(1024).decode()
        http_header = message.split('\r\n')
        extract_path = http_header[0].split()[1]
        #extract_path = extract_path.strip('/')

        try:
            my_file = open(extract_path, 'rb')
            file = my_file.read()
            my_file.close()
            temp_buffer = file
            tcpSocket.send("HTTP/1.1 200 OK\r\n\r\n".encode())
            tcpSocket.sendall(temp_buffer)
            tcpSocket.close()
        except FileNotFoundError:
            tcpSocket.send("HTTP/1.1 404 Not Found\r\n\r\n".encode())
            tcpSocket.close()
            return
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file tttl
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_socket.bind(("127.0.0.1", args.port))
        host_socket.listen(6)

        conn, addr = host_socket.accept()
        self.handleRequest(conn)

        host_socket.close()

        #x = 0
        #while x == 0:
            #x = 1
            #server_socket.listen(5)
            #conn, address = server_socket.accept()
            #x = self.handleRequest(conn)

        
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def proxyServer(self, conn):
        message = conn.recv(1024).decode()                                          #decodes the message send from the local host
        http_header = message.split('\r\n')                                         #splits the message so we just get the hostname
        http_method = http_header[0].split()[0]                                     #this gets which type of request the message is (DELETE/GET/PUT)
        extract_path = http_header[0].split()[1]
        extract_path = extract_path.strip('/')                                      #these two lines just gets the hosts name without the https or http 
        extract_path = extract_path.strip('https://')
        file_name = extract_path.replace(".","#")                                   #creates a file name for the website replaces the . with #
        file_name = file_name + ".html"                                             #adds .html as we want it to be a html file
        if(http_method.upper() == "GET"):                                           #if the html header is get
            try:                                                                    
                #will try to open a file with the file name created above and send the data back to the local host
                my_file = open(file_name, 'rb')
                print("FILE")
                file = my_file.read()
                my_file.close()
                print(file.decode())
                conn.send(file)
            except FileNotFoundError:                                                   #if the file doesn't exist it will go to this part of the function
                print("NO FILE")
                extract_name = socket.gethostbyname(extract_path)                           #changes the hostname into an ip
                return_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)           #creates a tcp socket to send the message to the hostname IP
                return_socket.connect((extract_name, 80))                                   #connects the hostname IP and port 80 (the reserved http port) together
                return_socket.send(message.encode())                                        #sends the message (sent from the local host) to the hostname IP
                data_buffer = ""                                                          #creates a data_buffer with nothing in it
                while True:                                                                 
                    data = return_socket.recv(1024)                                         #receives data from the socket that is connected to the hostname IP
                    data_decoded = data.decode()                                            #creates a new variable which has the data decoded as data is in bytes
                    data_buffer = data_buffer + data_decoded                                #adds data_decoded to the data_buffer
                    conn.send(data)                                                         #send the data to the local host
                    if("</html>\n" in data_decoded.lower()):                                #if data_decoded contains "</html>\n" it will break of the while true statement as it is the end of the file
                        break
                print(data_buffer)
                my_file = open(file_name ,'w')                                              #will create a file called the file name created above
                my_file.write(data_buffer)                                                  #writes the data_buffer to the file
                my_file.close()                                                             #closes the file
                return_socket.close()                                                       #closes the socket
        if(http_method.upper() == "DELETE" or http_method.upper() == "PUT"):            #if the http header is put or delete
            extract_name = socket.gethostbyname(extract_path)                           #changes the hostname into an ip
            return_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)           #creates a tcp socket to send the message to the hostname IP
            return_socket.connect((extract_name, 80))                                   #connects the hostname IP and port 80 (the reserved http port) together
            return_socket.send(message.encode())                                        #sends the message (sent from the local host) to the hostname IP
            while True:
                data = return_socket.recv(1024)                                         #receives data from the socket that is connected to the hostname IP
                data_decoded = data.decode()                                            #creates a new variable which has the data decoded as data is in bytes
                conn.send(data)                                                         #send the data to the local host
                print(data_decoded)
                if("</body>\n" in data_decoded.lower()):                                #if data_decoded contains "</body>\n" it will break of the while true statement as it is the end of the file
                    break
            return_socket.close()                                                       #closes the socket
        conn.close()                                                                 #closes the socket
        pass

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)             #creates a host socket type TCP
        host_socket.bind(("127.0.0.1", args.port))                                  #binds the tcp socket with the ip of localhost and the port specified    
        host_socket.listen(5)                                                       #listens for connections the maximum connections is specified with 5
        while True:
            try:                                                                 #will try to accept the connection from the localhost
                conn, addr = host_socket.accept()
                self.proxyServer(conn)
            except:
                exit()
                
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
