#receiver.py completed by Elliott Vercoe z3411256 on 20/10/18
import socket
import struct
import time
import sys

#Initialise the tracking statistics as a class so we can modify them globally
class Tracking:
    def __init__(self):
        self.total_segments_rec= 0
        self.data_segments_rec= 0
        self.error_segments_rec = 0
        self.dup_segments_rec = 0
        self.dup_acks_sent = 0

#Function to log a packet - this allows us to simply pass the function the packet, along with the event
#id, and it will be logged        
def log_packet(data,event):
    srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
    #Chose to use a single character flag, rather than multiple bits - this decodes that data
    if flag == 'R':
        flag = 'SA'
    log.append(["{:15}".format(event),"{:10.4f}".format(time.time()-startTime),\
                "{:5}".format(flag),"{:15}".format(seqnum),"{:15}".format(len(message)),"{:15}".format(acknum)])                

#Utilises the struct.pack to convert our header items to bytes and pack them into a header. Returns the header and the message.                 
def encode_udp_message(srcudp, destudp, seqnum, acknum, hlength, flag, message):
    srcudp = struct.pack('h',srcudp-32768)
    destudp  = struct.pack('h',destudp-32768)
    seqnum = struct.pack('i',seqnum)
    acknum = struct.pack('i',acknum)
    hlength = struct.pack('h',hlength)
    flag = flag.encode()
    #Calculate the checksum for the encoded data. Packs it into 2 bytes.
    checksum = sum(srcudp + destudp+seqnum+acknum+hlength+flag+message)
    checksum = struct.pack('h', checksum % 32767)
    return b''.join([srcudp,destudp,seqnum,acknum,hlength,flag,checksum,message])

#Decodes the message that we have encoded using the above function
def decode_udp_message(data):
    srcport = struct.unpack('h',data[0:2])[0]+32768
    destport = struct.unpack('h',data[2:4])[0]+32768
    seqnum = struct.unpack('i',data[4:8])[0]
    acknum = struct.unpack('i',data[8:12])[0]
    hlength = struct.unpack('h',data[12:14])[0]
    flag = data[14:15].decode()
    checksum = struct.unpack('h',data[15:17])[0]
    message = data[17::]
    return srcport, destport, seqnum, acknum, hlength, flag, message

#Given a packet, checks whether the checksum is correct (has the packet been corrupted)?    
def failed_checksum(data):
    checksum = struct.unpack('h',data[15:17])[0]
    calcedsum = sum(data[:15]) + sum(data[17:])
    if checksum == calcedsum:
        return False
    else:
        return True

#From here, these functions define the actions that are taken throughout operation. They can be read in chronological order
#to get a sense of what is going on.

#State 1 - Waiting for ACK
def wait_for_syn(sock):
    global destip
    global startTime
    while True:
        data, addr = sock.recvfrom(1024)
        #Take the first value received and strip the UDP header for the IP address.
        #Note that we encode the port number in the message, but not the IP, much like TCP does.
        destip = addr[0]
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        #Record the starting time in a global variable
        startTime = time.time()
        
        #Check if we have received a syn message - otherwise ignore it.
        if flag == 'S':
            #Track and log the segment we have received
            Tracker.total_segments_rec += 1
            log_packet(data,'rcv')
            #Send a response, iterating the seqnum by 1
            synackresponse = encode_udp_message(srcport,destport,acknum,seqnum + 1,hlength,'R',b'')
            sock.sendto(synackresponse,(destip,srcport))
            log_packet(synackresponse,'snd')
            #Enter the wait_for_ack phase
            wait_for_ack(sock)
            return
def wait_for_ack(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        #Once we receive a valid ack, log it and track it, and continue into the receiving message stage
        if flag == 'A':
            log_packet(data,'rcv')
            Tracker.total_segments_rec += 1
            return
            
#State 2 - Receiving Message          
#This is the primary stage, in which the receiver waits for data, and shoots off the relevant acks in response
def receiving_message(sock,final_message):
    while True:
        data, addr = sock.recvfrom(1024)
        Tracker.total_segments_rec += 1
        
        #Check the checksum, and silently discard the packet if it fails.
        if failed_checksum(data):
            Tracker.error_segments_rec += 1
            log_packet(data,'rcv/corr')
            continue
          
        #Receive and decode the data
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
           
        #If we receive a 'F' flag, respond with a fin ack, then continue to Stage 3 - wrapping up
        if flag == 'F':
            log_packet(data,'rcv')
            respond_fin_ack(sock,srcport, destport, seqnum, acknum, hlength, flag)
            return
            
        Tracker.data_segments_rec += 1  
        log_packet(data,'rcv')   
        
        #If we have not seen the seqnum of the packet before
        if seqnum not in packets.keys():
            #Add the message to the list of packets
            packets[seqnum] = message
            
            #If the message is in order, append the data to the end and send the appropriate ack
            if seqnum == len(final_message):
                final_message += list(message)
                data = send_ack(sock,srcport, destport, len(final_message), acknum, hlength, flag)
                log_packet(data,'snd')
                
            #If the message is not in order, store the message in a buffer, and send an ack for the last highest received message
            else:
                received_buffer[seqnum] = message
                Tracker.dup_acks_sent += 1
                data = send_ack(sock,srcport, destport, len(final_message), acknum, hlength, flag)
                log_packet(data,'snd/DA')
                
            #Check if we have anything in the buffer. If we do, check if we can now patch the sequences together.
            for seq in sorted(received_buffer.keys()):
                if seq == len(final_message):
                    final_message += list(received_buffer[seq])
                    received_buffer.pop(seq)
                    
        #Else if we have seen the packet before, respond with latest ack.
        else:
            Tracker.dup_segments_rec += 1
            data = send_ack(sock,srcport, destport, len(final_message), acknum, hlength, flag)
            log_packet(data,'snd/DA')
                       
def send_ack(sock,srcport, destport, seqnum, acknum, hlength, flag):
    ackresponse = encode_udp_message(srcport,destport,acknum,seqnum,hlength,'A',b'')
    sock.sendto(ackresponse,(destip,srcport))
    return ackresponse

#Responds with a fin, then immediately with an ack    
def respond_fin_ack(sock,srcport, destport, seqnum, acknum, hlength, flag):
    ackresponse = encode_udp_message(srcport,destport,acknum,seqnum,hlength,'A',b'')
    log_packet(ackresponse,'snd')
    sock.sendto(ackresponse,(destip,srcport))

    finresponse = encode_udp_message(srcport,destport,acknum,seqnum,hlength,'F',b'')
    log_packet(finresponse,'snd')
    sock.sendto(finresponse,(destip,srcport)) 

#State 3 - Closing connection
#Waits for the final ack to indicate the connection is closed
def close_connection(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        if flag == 'A':
            Tracker.total_segments_rec += 1
            log_packet(data,'rcv')
            break  

#Declare some global variables
Tracker = Tracking()
log = []
startTime = time.time()    
packets = {}
final_message = []
received_buffer = {}
destip = None
    
if len(sys.argv) != 3:
    print('incorrect arguments')
args = sys.argv
 
UDP_IP = '127.0.0.1'
UDP_PORT = int(args[1])
filename = args[2]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

#Initiate Stage 1
wait_for_syn(sock)
#Initiate Stage 2
receiving_message(sock,final_message)
#Initiate Stage 3
close_connection(sock)

#Decode the received message and write it to a file
decodedlist = bytes(final_message)
with open(filename,'wb') as f:
    f.write(decodedlist)
        
#Write log to file
with open('Receiver_log.txt','w') as f:
    for entry in log:
        f.write('\t'.join(entry) + '\n')
    f.write('=============================================================\n')
    f.write("{:50}".format('Amount of data received (bytes)')+str(len(decodedlist))+'\n')
    f.write("{:50}".format('Total Segments Received ')+str(Tracker.total_segments_rec)+'\n')
    f.write("{:50}".format('Data segments received ')+str(Tracker.data_segments_rec)+'\n')
    f.write("{:50}".format('Data segments with Bit Errors')+str(Tracker.error_segments_rec)+'\n')
    f.write("{:50}".format('Duplicate data segments received')+str(Tracker.dup_segments_rec)+'\n')
    f.write("{:50}".format('Duplicate ACKs sent')+str(Tracker.dup_acks_sent)+'\n') 
    f.write('=============================================================\n')    

print('finished')