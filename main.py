import socket
import threading
import select
import re
import requests

lvl = False

like = False

lvlnew = None


SOCKS_VERSION = 5


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

        while True:
            conn, addr = s.accept()
            running = False
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
    def botdev(self, client, remote, address, port):
        global group
        activation = True
        group = None
        while True:

            r, w, e = select.select([client, remote], [], [])
            if client in r or remote in r:
                if client in r:
                    dataC = client.recv(999999)
                    
                    if port == 39699:
                        
                        
                        group = remote
                    if remote.send(dataC) <= 0:
                        break
                if remote in r:
                    global actcode
                    

                    dataS = remote.recv(999999)
                    
                    
                                    

                    try:
                        
                        
                        
                        global lvl
                        global lvlnew
                        global like
                        import time
                        import threading
                        
                        dataS_hex = dataS.hex()  # 
                       
                        if like == True :
                        	
                       # 	threading.Thread(target=top_fire).start()
                        #	like = False

                        #	time.sleep(2)                        	                        	
                        	                     #   	like
                        	group.send(bytes.fromhex("0315000000107876b41e9de83607618490c15cd33c27"))
                        	
                        	
                        
                        #"0000273727303150000737373737"
                        
                      #  lvl = False
                        
                   #     
                      
                       
                        
                        
                        	
                        	
                        	
                        	
                        	  
                        
                                    
                        
                        
                        if  lvl == True and "0315" in dataC.hex()[0:4]:
                        	 print(dataC.hex())
                        	 print(dataC)
                        	 lvlnew = dataC
                        #	 run_lvl = True
                        
               #         def runl():
                        	 
                       # 	 global 
                        	 
                        	 
                       # 	 while lvlnew !=	None:
                        	 	
                        	 	
                        	 
                        	 
                        	
                        
                       
                        if "1200" in dataS.hex() [0:4] and  b"/start" in dataS:


                        	print("DOneeeee")
                        	
                        	response = "051500000010553557f996c386cfd1d2548c60c2bdaa"
                        	group.send(bytes.fromhex(response))
                        	
                        	
           #             
                        if '1200' in dataS.hex()[0:4] and b'make' in dataS :
                            clin.send(bytes.fromhex("051500000010553557f996c386cfd1d2548c60c2bdaa"))
                                      
#	                   
#                            
                    except:
                        pass


                    if client.send(dataS) <= 0:
                        break

                     
def top_fire():
	  for e in range(10):
	  	group.send(bytes.fromhex("120000007108af94c7ec1c101220022a6508af94c7ec1c10af94c7ec1c220d5be323d3930343039303032325d28a7a58fa7064a380a22efbcb3efbcb0e28194efbca5efbcaefbcafefbcae5fefbca4efbcafefbcaeefbca510df8b90ae0318e7efd2ad03201328c1b7f8b1035202656e6a0410011801"))
             
	  
	 	
	 	
	 
	 
	 
	 
	                                                         
	                                                         
def starttopbot():
	
	

    Proxy().run('127.0.0.1',1080)
starttopbot()

