import socket
import threading
import select
import re
import requests

a="\033[1;30m"
b="\033[1;31m"
c="\033[1;32m"
d="\033[1;34m"

e="\033[1;34m"
f="\033[1;35m"
g="\033[1;36m"

add_frind = False
run = False

SOCKS_VERSION = 5

spy_id = False

id_add = None
import  os
clin = None
clear = False
recorde = False
spy_normall = None
lvl = False
group = None
clin2 = None
send_go = False
dex = False
packt_lag = None

inter_group = None

lag_id_check = False

def inter():
    while True:
        global lag_id_check , inter_group
        global send_go, packt_lag,dex
        global clear,recorde , spy_normall
        vasd=input("SEND ID >")
        global lvl,head,group ,clin ,clin2 ,id_add
        
        if 'lag' in vasd and packt_lag != None:
        	
        	
        	    print("send lag_go")
        	    lag_id_check = True   
        	    threading.Thread(target=lag_id, args= (packt_lag,)).start()
        	
        	
        elif "st" in vasd :
        	
        	#dex=False
        	lag_id_check = False
        	
        elif "s" in vasd :
        	
        	if inter_group != None :
        		group.send(inter_group)
          	        	
    #    	lag_id(packt_lag)
        	
        #	threading.Thread(target=inter, args=()).start()
        	
        #	
        	
    #    elif 
        	
        elif "2" in vasd:
        	
        	yor_id = vasd
        	
        	print("send msg")
        	
        	send_go = True
        	

                        	
                               
        	clin2.send(bytes.fromhex(f"120000013808efd2edba0c101220022aab0208{id_add}10efd2edba0c18022889e7aba8063803428c017b22636f6e74656e74223a22545f32365f415f504f5f4d45535f31222c22697352657175657374223a747275652c2269734163636570746564223a66616c73652c22726561736f6e223a302c2274696d65223a302c2267616d65537461727454696d65223a302c226d617463684d6f6465223a302c2267616d654d6f6465223a302c226d61704944223a307d4a2c0a15d981d8b1d8b5d9875fd8b3d8b9d98ad8afd9873a2910b6c58fae0318bea9d2ad0320d90128d9aff8b1035202656e6a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3731363937353732323035333131382f706963747572653f77696474683d313630266865696768743d31363010011801"))

        	
        	
        	
          	

        	
        	

         	
        	
        
                	
         	

def lag_id(packt):
        
            import time
            global lag_id_check, group,dex
            
            while lag_id_check  == True :
            	try:
            		print(c,"sending to ",b,packt.hex())
            		
            		time.sleep(0.02)
            		
            		
            		
            		group.send(packt)
            		group.send(packt)
            		
            		
            	except:pass
	     	
            		
            	
            	
            	
            
            
            
            
            
   
        
            
head = None            

start = None
            

class Proxy:
 
    def __init__(self):
        self.username = "username"
        self.password = "username"
        self.packet = b''
        self.sendmode = 'client-0-'

    def handle_client(self, connection):

        version, nmethods = connection.recv(2)

        methods = self.get_available_methods(nmethods, connection)

        if 2 not in set(methods):

            connection.close()
            return

        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection):
            return

        version, cmd, _, address_type = connection.recv(4)
        

        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
 
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
            name= socket.gethostname()

        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
            else:
                connection.close()

            addr = int.from_bytes(socket.inet_aton(
                bind_address[0]), 'big', signed=False)
            port = bind_address[1]

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')

            ])
        except Exception as e:

            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        if reply[1] == 0 and cmd == 1:
            self.botdev(connection, remote, address, port2)
        connection.close()

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        version = ord(connection.recv(1))


        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:

            response = bytes([version, 0])
            connection.sendall(response)
 
            return True
            

        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        var = 0 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()
        print(" [ free fire proxy  ] [your ip {}]:[ the port {}]".format(host, port))
        threading.Thread(target=inter, args=()).start()

        while True:
            conn, addr = s.accept()
            running = False
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
    def botdev(self, client, remote, address, port):
        global group
        activation = True
       
        global clin , clin2 ,send_go,inter_group
        while True:

            r, w, e = select.select([client, remote], [], [])
            
            
               	
               	    		
                    		
            if client in r or remote in r:
                if client in r:
                    dataC = client.recv(99999999)
                    global packt_lag
                    
                    if "0515" in dataC.hex()[0:4] and len(dataC.hex()) < 400 and send_go == True :
                    	packt_lag = dataC
                    	
                    	
                    	



                        
                    	

                    	print("\n\n ", dataC.hex(),"\nhereeee\n")
                    	
                   
                    if send_go == True and "0515" in dataC.hex()[0:4] and len(dataC.hex()) > 1100 :
                    	inter_group = dataC
                    	
                    	
                    	
                    	send_go = False
                    	
                    if send_go == True and "0515" in dataC.hex()[0:4] :
                    	print("\n\n len data :" , len(dataC.hex()))
                    	print("\n\n" ,dataC.hex())
                    	
                    	
                    if port == 39800 :
                    	clin2 = client
                    if port == 39698:
                        
                        group = remote                        
                        clin = client
                        
                      
                        
                    if remote.send(dataC) <= 0:
                        break
                if remote in r:
                    global actcode

                    dataS = remote.recv(999999)
                    
                    def packet_fixer(packet):
                                                                           packet = packet.lower()
                                                                           packet = packet.replace(" ","")
                                                                           return packet
                                                                           
                                                                           

                    try:
                    	
                    	global a,c,b
                    	global run
                    	global add_frind, spy_id
                    	import random
                    	global id_add, clear,recorde
                    	b="\033[1;31m"
                    	c="\033[1;32m"
                    	global lvl
                    	global start , spy_normall
                    	global head
                    	
                 
             	
             	
             	
                    	if port == 39698 and "0f0000" in dataS.hex()[0:6] and len(dataS.hex())  == 52 and "0f15" in dataC.hex()[0:4] and len(dataC.hex()) == 44 :
                    		id_add = dataS.hex()[-10:]
                    		
                    		print("\n\n\nid = ", id_add)
                    		
                    		clin.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b3030464630305d4e4554e385a4424f542b2b5b3030464646465d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))

                    	
                    	elif port == 39698 and "0f0000" in dataS.hex()[0:6] and len(dataS.hex())  < 130 and dataS.hex()[-4:] == "1005" and "0f15" in dataC.hex()[0:4] and len(dataC.hex()) == 44 :
                    		id_add = dataS.hex()[40:50]
                    		
                    		print("\n\n\nid = ", id_add)
                    		
                    		clin.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b3030464630305d4e4554e385a4424f542b2b5b3030464646465d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))

                       
                    	
                    	
                    	
                 #   	if "0515" in dataC.hex()[0:4] :
                    #		print("\n\n ::::>",dataC.hex(),"\n\n")
                    		
                    	
              #      	if port == 39699 and "0f1500000010" in dataC.hex() :
                    #		print("\n\n ::::>",dataC.hex(),"\n\n")
                    	
                    	
                    	if  '0500' in dataS.hex()[0:4] and '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141and len(dataS.hex())>=100:
                    		
                    		spy_normall = dataS
                    		head = client
                    		print("new group 2 ")
                    	
                    		
                    #		print(f"\n\nNew group\n\n{dataS}\n\n")
                    		                    #		spy_normall = dataS


                  
                          
                
                   #  
#                       if "0515" in dataC.hex()[0:4] and len(dataC.hex()) > 1100 :
#                           inter_group = dataC
#                           group.send(inter_group)
                            
                    	if "1200" in dataS.hex() [0:4] and  b"/lag" in dataS:
                            response = "0315000001c062de5631d0c9f117d8b60c5cb9de5145c770e3288d94083f17d1915bd7f301cbe5802b6318af4e7c5b80c60fe0dff669889161daac634ea38762d48021fa34e901291f945c6680df94420f7668b9880fddc28385177e11f1fe94c975a1cadf81c19018c18b25047fca2e4933a8e65527858c4ef9aa8ccc3d1d56dfb1c458df3dc2a1bf8278ea8bd4704928897274e04dbdec8c78226e461c425a97ec1abad3e5d46a748158b2a4829dc67dcbd1294d02f0219d874313cff2fc3fa50301bf9d177627d1afaf11d938d7472750e104189624885ec3223ec74be91d6308a3c7cb71ce7a20d797deaf4c16ef067c3cf64ab59041e5258cf12be6784ac7530ac44c44fcdd2a1911973ae6aec58b7b43dbc54ad6b0d01a374c48156871277006d9a72e4151acfd6063d8ae046a21c094166b79c045a6d9cb944ff3b724a4a4147d31a9e34569a169020bce04fbc06c36be5abd2290cf22f1692c189852cc54863d9ac681ef38472988a47ae9ec0c7117ac1d89e675589dedbabc33ad7c970e7c8cfd7590b30eb3553c64e09285f64ed2c38fa9d0f91739e1903648962c41b53272e2f42b347eb350f3ff3b5f812df81875e8c07cf2d3bdb036e00373b44827ed8776f8"
                            group.send(bytes.fromhex(response))
     
                     	    	
                    	if "1200" in dataS.hex() [0:4] and  b"/start" in dataS:
                    	    
                    	    responsfe = "0515000000104d8842ec06f94942d03d8887e7a97735"
                    	    
                    	    group.send(bytes.fromhex(responsfe))
                    	   
                    	    print("DOneeeee")	
                    	
                    	if "1200" in dataS.hex() [0:4] and  b"/sd" in dataS:
                    	    
                    	    for i in range(150):
                    	        
                    	        
                    	        response = "0515000000104d8842ec06f94942d03d8887e7a97735"
                    	   
                    	        group.send(bytes.fromhex(response))
                    	   
                    	           
                    	        
                    	if lvl == True :
                    		print("send LVL")
                    		
                    		stop_lvl =b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8'
                    		group.send(stop_lvl)
                    		group.send(start)
                    		
                    	#	lvl = False
                    	       


                        	
                        	
                        	
                        	
                    	if '0315' in dataC.hex()[0:4] and port == 39699  and len(dataC.hex()) > 750 and lvl == True  :
                    		
                    		
            		
                    			start = dataC
                    			print("data - LvL")
                    			print(dataC.hex())
                    			
                    		
                    		
                    	
                    	if clear == True:
                    		os.system('clear')
                    		clear = False
                    	


                    	if port == 39698 and recorde == True:
                    		
                    		print(b,"DATA.S server : ",dataS.hex(),a,"\n\n")
                    		print(c,"DATA.C clinte : ",dataC.hex(),a , "\n\n")                    	
                    	
                    	if "1200" in dataS.hex() [0:4] and  b"/spy" in dataS:
                    		
                    		spy_id = True
                    		
                    		
                    		
         	
                    	                  	                  	
                    	
                    	
                    except:
                        print("rerror")

                    if client.send(dataS) <= 0:
                        break	 
                                        
def starttopbot():

    Proxy().run('127.0.0.1',7777)
starttopbot()
