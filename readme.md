1) Run the Receiver with the following command:
python receiver.py receiver_port file_r.pdf  

A sample input would be the following:
python receiver.py 8001 file_r.pdf


2) Run the Sender with the following command:
python sender.py receiver_host_ip receiver_port file.pdf MWS MSS gamma pDrop pDuplicate pCorrupt pOrder maxOrder pDelay maxDelay seed 

A sample input would be the following:
python sender.py 127.0.0.1 8001 file_r.pdf 500 100 4 0.1 0.1 0.1 0.1 5 0.1 1 50


3) View the output logs.
The sender output log contains the following:
- Size of the file (in Bytes)
- Segments transmitted (including drop & RXT)  
- Number of Segments handled by PLD
- Number of Segments Dropped
- Number of Segments Corrupted  
- Number of Segments Re-ordered 
- Number of Segments Duplicated 
- Number of Segments Delayed 
- Number of Retransmissions due to timeout 
- Number of Fast Retransmissions  
- Number of Duplicate Acknowledgements received

The receiver output log contains the following:
- Amount of Data Received (bytes) 
- Total segments received 
- Data segments received  
- Data Segments with bit errors 
- Duplicate data segments received
- Duplicate Acks sent 