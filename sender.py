#sender.py completed by Elliott Vercoe z3411256 on 20/10/18
import socket
import struct
import time
import random
import threading
import sys

#Initialise the tracking statistics as a class so we can modify them globally
class Tracking:
    def __init__(self):
        self.total_transmitted = 0
        self.pld_handled = 0
        self.num_dropped = 0
        self.num_corr = 0
        self.num_rord = 0
        self.num_dup = 0
        self.num_delayed = 0
        self.num_retrans_to = 0
        self.num_retrans_fast = 0
        self.num_dup_acks = 0
    
#PLD Module - generates a random number based on the seed and decides what action to undertake
def pldsend(sock,message,ports,overwrite=False,RXT = ''):
    global packets_sent
    global queued_packet
    
    #Track the packet coming through
    Tracker.total_transmitted += 1
    
    #Check if we have sent enough packets so that we can send the reordered one
    if (packets_sent == maxorder) and maxorder:
        log_packet(queued_packet,'snd/rord' + RXT)
        sock.sendto(queued_packet,ports)
        queued_packet = None
        packets_sent = 0
        
    #If the packet is coming from the SYN/FIN phase, send it straight through
    if overwrite:
        log_packet(message,'snd' + RXT)
        sock.sendto(message,ports)
        return
    
    #Track the packet being handled by the module
    Tracker.pld_handled += 1
    
    #A) Chance to drop the packet
    if random.random() < pDrop:
        log_packet(message,'snd/drop' + RXT)
        Tracker.num_dropped += 1
        return
        
    #B) Chance to duplicate
    if random.random() < pDuplicate:
        log_packet(message,'snd/dup' + RXT)
        Tracker.num_dup += 1
        sock.sendto(message,ports)
        sock.sendto(message,ports)
        return
        
    #C) Chance to corrupt
    if random.random() < pCorrupt:
        log_packet(message,'snd/corr' + RXT)
        Tracker.num_corr += 1
        sock.sendto(flip_bit(message),ports)
        return
        
    #D) Out of sequence
    #Store the packet in a queue, and track how many packets are sent afterwards.
    #When the release number is met, or another packet is put in the queue, send the packet
    if random.random() < pOrder:
        Tracker.num_rord += 1
        if queued_packet:
            log_packet(queued_packet,'snd/rord')
            sock.sendto(queued_packet,ports)
        queued_packet = message
        packets_sent = 0
        return
        
    #E) Delay packet send
    #Opens a new thread with a delay to send the packet
    if random.random() < pDelay:
        Tracker.num_delayed += 1
        t = threading.Timer(random.random()*MaxDelay/1000,sock.sendto,[message,ports])
        t.start()
        return
    
    #Keep track of the number of packets which have been sent since a packet was last reordered
    if queued_packet:
        packets_sent += 1
        
    #If none of the above conditions are met, send the packet through cleanly.
    log_packet(message,'snd' + RXT)
    sock.sendto(message,ports)

#This function imitates flipping a bit in the checksum. It takes a random location in the 
#bytes array, and modifies the value of that byte by 2^1 to 2^8, to emulate a flipped bit.
#Although the bit is not exactly flipped, this will emulate corruption exactly.    
def flip_bit(data):
    loc = random.randint(0,len(data)-1)
    flipped = random.choice([1,2,4,8,16,32,64,128])
    newval = struct.pack('?',(data[loc] + flipped) % 256)
    data = b''.join([data[:loc],newval,data[loc+1:]])
    return data
    
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

#Function to log a packet - this allows us to simply pass the function the packet, along with the event
#id, and it will be logged      
def log_packet(data,event):
    srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
    #Chose to use a single character flag, rather than multiple bits - this decodes that data
    if flag == 'R':
        flag = 'SA'
    log.append(["{:15}".format(event),"{:10.4f}".format(time.time()-startTime),\
                "{:5}".format(flag),"{:15}".format(seqnum),"{:15}".format(len(message)),"{:15}".format(acknum)])
    
#Encode the message into each packet. This has been performed all at once, due to the specification requirement that 
#data in the payload is only transmitted in 1 direction - so that acks during the message transmission phase are the same
def encode_message(encoded_message,message,src_udp_port,dest_udp_port,seqnum,acknum,headerlength,max_packet_size):
    i = seqnum
    #Generate each packet and store in a dictionary
    while i*max_packet_size < len(message):
        encoded_message[i*max_packet_size] = encode_udp_message(src_udp_port,dest_udp_port,i*max_packet_size,acknum,headerlength,'D',message[i*max_packet_size:(i+1)*max_packet_size])
        i += 1
    encoded_message[len(message)] = encode_udp_message(src_udp_port,dest_udp_port,len(message),acknum,headerlength,'D',message[i*max_packet_size:len(message)])
    #For each packet, use a separate dictionary to check if the packet has been acked
    acked_packets = {}
    for key in encoded_message.keys():
        acked_packets[key] = 0
    return acked_packets
    
    
#From here, these functions define the actions that are taken throughout operation. They can be read in chronological order
#to get a sense of what is going on.

#State 1 - Perform 3 way handshake
#Send the initial syn message with no payload
def send_syn(sock,src_udp_port,dest_udp_port,initialseqnum,initialacknum,headerlength):
    initialsyn = encode_udp_message(src_udp_port,dest_udp_port,initialseqnum,initialacknum,headerlength,'S',b'')
    pldsend(sock,initialsyn,(dest_udp_ip,dest_udp_port),True)
    return wait_for_synack(sock)

def wait_for_synack(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        #If the packet has the correct flag, leave the wait_for_synack phase and initiate Stage 2 - sending message
        if flag == 'R':
            #Log the packet
            log_packet(data,'rcv')
            initialack = encode_udp_message(src_udp_port,dest_udp_port,seqnum,acknum,headerlength,'A',b'')
            #Send the packet through PLD - noting the flag True indicating the message must not be handled by PLD
            pldsend(sock,initialack,(dest_udp_ip,dest_udp_port),True)
            return
        
    
#State 2 - Sending Message
#The following functions provide ease-of-use tools to navigate packet keys and the order of them.
#This function returns the minimum packet that has not been acked
def min_unacked_packet(acked_packets):
    for i in sorted(acked_packets.keys()):
        if not acked_packets[i]:
            return i
    return False
#This function works out the seqnum of the packet n packets forward.
def later_packet(acked_packets,location,n):
    listofkeys = sorted(acked_packets.keys())
    for i in range(len(listofkeys)):
        if listofkeys[i] == location:
            if i + n < len(listofkeys) and i + n >= 0:
                return listofkeys[i+n]
            else:
                return False
#The following functions return the seqnum of the packet immediately before or after the packet of interest
def next_packet(acked_packets,location):
    return later_packet(acked_packets,location,1)
def previous_packet(acked_packets,location):
    return later_packet(acked_packets,location,-1)

#This is the main driver of the message sending phase. It will continue to send packets as it is allowed to,
#and will connect to the wait_for_ack function when it is required to wait
def send_message(sock,encoded_message,dest_udp_ip,dest_udp_port,acked_packets):
    #Find the minimum unacked packet
    minunacked = min_unacked_packet(acked_packets)
    #Find the last packet, so we know when to stop sending packets
    maxkey = max(encoded_message.keys())
    
    #While there is still a minimum unacked packet, keep sending
    while True:
        #For each unacked packet from the minimum to the end of the window
        for extrapacket in range(MWS):
            #Find the seqnum of the packet that needs to be sent
            seqnum = later_packet(acked_packets,minunacked,extrapacket)
            #If the seqnum is higher than the greatest seqnum, stop sending (this utilises the later_packet return False functionality)
            if not seqnum:
                if minunacked:
                    break
            #If the seqnum is in the window, but we are waiting on an ack, check the next seqnum in the window
            if seqnum in activewindow:
                continue
            #If the seqnum is in the window, and an ack has not yet been received, send the packet
            if not acked_packets[seqnum]:
                activewindow.add(seqnum)
                pldsend(sock,encoded_message[seqnum],(dest_udp_ip,dest_udp_port))
                
        #Wait for the ack for the packet in the window with the minimum sequence number
        first_time = True
        while wait_for_ack(sock,next_packet(acked_packets,minunacked),0,first_time):
            #If we timeout while waiting, send the minimum packet again
            activewindow.add(seqnum)
            pldsend(sock,encoded_message[minunacked],(dest_udp_ip,dest_udp_port),False,RXT='/RXT')
            first_time = False
        
        #Check what the new minimum unacked packet is, and restart the loop from there
        minunacked = min_unacked_packet(acked_packets)
        #If we are up to the last packet, we are finished and can move to the next stage
        if minunacked == maxkey:
            return
    
def wait_for_ack(sock,goalseqnum,timespent,first_time=False):
    print('waiting for ack',goalseqnum)
    global estimatedRTT
    global devRTT
    global timeoutinterval       
    
    #Check that we have a valid sequence number
    if not goalseqnum:
        return False
    
    while True:
        #Set the timeout value. Note that the timespent value keeps track of the time spent in 
        #previous iterations of the loop. This way, even if we receive an ack from a different packet
        #the timer will continue
        timeout = timeoutinterval - timespent
        sock.settimeout(timeout)
        #Wait to receive the data - if we timeout, break the function and send again
        try:
            started = time.time()
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            Tracker.num_retrans_to += 1
            return True
        
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        
        #If we receive the ack we are waiting for, set this packed to acked, and exit the loop
        if flag == 'A' and acknum == goalseqnum:
            acked_packets[previous_packet(acked_packets,acknum)] = 1
            log_packet(data,'rcv')
            #Remove this packet from the active window as we have received its ack
            activewindow.remove(previous_packet(acked_packets,acknum))
            #Update the timers in accordance with the RTT
            #Only update if its the first time sending
            if first_time:
                sampleRTT = time.time() - started + timespent
                estimatedRTT = 0.875 * estimatedRTT + 0.125 * sampleRTT
                devRTT = 0.75 * devRTT + 0.25 * abs(sampleRTT - estimatedRTT)
                timeoutinterval = estimatedRTT + gamma * devRTT
            return False
            
        #If we receive a ack greater than the number we are waiting for, update each acked packet
        #up to that packet, and continue the loop
        elif flag == 'A' and acknum > goalseqnum:
            log_packet(data,'rcv')
            for i in range(previous_packet(acked_packets,goalseqnum),previous_packet(acked_packets,acknum)+1):
                if i in acked_packets.keys():    
                    acked_packets[i] = 1
                    #Make sure to remove each packet from the active window
                    if i in activewindow:
                        activewindow.remove(i)
            return False        
            
        #If we receive a packet less than the number we are waiting for...
        elif flag == 'A' and acknum < goalseqnum:
            log_packet(data,'rcv/DA')
            Tracker.num_dup_acks += 1
            #We check how many times we have received this ack in case we have to fast retransmit
            acked_packets[previous_packet(acked_packets,acknum)] += 1
            if acked_packets[previous_packet(acked_packets,acknum)] == 3:
                Tracker.num_retrans_fast += 1
                return True
            #If we do not need to fast retransmit, restart the loop with the adjusted time
            return wait_for_ack(sock,goalseqnum,timespent + started-time.time(),first_time)
             
    
#State 3 - Closing Connection
def finish_connection(sock,src_udp_port,dest_udp_port,seqnum,acknum,headerlength):
    #Send the fin packet
    finpacket = encode_udp_message(src_udp_port,dest_udp_port,seqnum,acknum,headerlength,'F',b'')
    pldsend(sock,finpacket,(dest_udp_ip,dest_udp_port),True)
    #Wait for the fin, then the ack
    wait_for_finack(sock)
    #Then send the final ack and close the connection
    send_final_ack(sock,src_udp_port,dest_udp_port,seqnum,acknum,headerlength)
    
def wait_for_finack(sock):
    while True:
        sock.settimeout(30)
        data, addr = sock.recvfrom(1024)
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        if flag == 'A':
            log_packet(data,'rcv')
            break
    while True:
        sock.settimeout(30)
        data, addr = sock.recvfrom(1024)
        srcport, destport, seqnum, acknum, hlength, flag, message = decode_udp_message(data)
        if flag == 'F':
            log_packet(data,'rcv')
            break
    
def send_final_ack(sock,src_udp_port,dest_udp_port,seqnum,acknum,headerlength):
    finalack = encode_udp_message(src_udp_port,dest_udp_port,seqnum,acknum+1,headerlength,'A',b'')
    pldsend(sock,finalack,(dest_udp_ip,dest_udp_port),True)

#Define a few global variables
packets_sent = 0
queued_packet = None
startTime = time.time()
Tracker = Tracking()   

#Check the sanitation of our input arguments
if len(sys.argv) != 15:
    print('incorrect arguments')
args = sys.argv

#Input variables for sender
dest_udp_ip = args[1]
dest_udp_port = int(args[2])
filename = args[3]

max_packet_size = int(args[5])
MWS = int(int(args[4])/max_packet_size)
gamma = int(args[6])

#Input variables for PLD module
pDrop = float(args[7])
pDuplicate = float(args[8])
pCorrupt = float(args[9])
pOrder = float(args[10])
maxorder = int(args[11])
pDelay = float(args[12])
MaxDelay = float(args[13]) #in ms
seed = float(args[14])

#Generate random seed
random.seed(seed)

#Variables generated for transfer operation
message = open(filename,'rb').read()
headerlength = 17
initialseqnum = 0
initialacknum = 0
encoded_message = {}
estimatedRTT = 0.5
devRTT = 0.25
timeoutinterval = estimatedRTT + 4 * devRTT
activewindow = set()
log = []

#Opening socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
src_udp_ip = '127.0.0.1'
sock.bind(('', 0))
src_udp_port = sock.getsockname()[1]
print('bound to port',src_udp_port)


#Initiate Stage 1    
send_syn(sock,src_udp_port,dest_udp_port,initialseqnum,initialacknum,headerlength)
#Encode the packets
acked_packets = encode_message(encoded_message,message,src_udp_port,dest_udp_port,0,1,headerlength,max_packet_size)
#Initiate Stage 2
send_message(sock,encoded_message,dest_udp_ip,dest_udp_port,acked_packets)
#Initiate Stage 3
finish_connection(sock,src_udp_port,dest_udp_port,max(encoded_message.keys()),1,headerlength)

sock.close()

#Write log to file
with open('Sender_log.txt','w') as f:
    for entry in log:
        f.write('\t'.join(entry) + '\n')
    f.write('=============================================================\n')
    f.write("{:50}".format('Size of the file (in Bytes)')+str(len(message))+'\n')
    f.write("{:50}".format('Segments transmitted (including drop & RXT)')+str(Tracker.total_transmitted)+'\n')
    f.write("{:50}".format('Number of Segments handled by PLD')+str(Tracker.pld_handled)+'\n')
    f.write("{:50}".format('Number of Segments dropped')+str(Tracker.num_dropped)+'\n')
    f.write("{:50}".format('Number of Segments Corrupted')+str(Tracker.num_corr)+'\n')
    f.write("{:50}".format('Number of Segments Re-ordered')+str(Tracker.num_rord)+'\n')
    f.write("{:50}".format('Number of Segments Duplicated')+str(Tracker.num_dup)+'\n')
    f.write("{:50}".format('Number of Segments Delayed')+str(Tracker.num_delayed)+'\n')
    f.write("{:50}".format('Number of Retransmissions due to TIMEOUT')+str(Tracker.num_retrans_to)+'\n')
    f.write("{:50}".format('Number of FAST RETRANSMISSION')+str(Tracker.num_retrans_fast)+'\n')
    f.write("{:50}".format('Number of DUP ACKS received')+str(Tracker.num_dup_acks)+'\n')
    f.write('=============================================================\n')

print('finished')