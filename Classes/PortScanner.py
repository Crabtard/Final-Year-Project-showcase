#here is a portscaner, put all the idv files into one so importing into GUI is easier

from scapy.all import *
import datetime
#from cryptography.fernet import Fernet
import EncDec

class Port_Scanner:

    def __init__(self, target_ip, target_ports):
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.Results = [] #list to store the results of the scan

        #self.key = Fernet.generate_key()
        #self.f = Fernet(self.key)

        #with open("key.key", "wb") as key_file:
        #    key_file.write(self.key)

    '''def encrypt(self, data):

        encrypted_data = self.f.encrypt(data.encode())
        return encrypted_data'''
    
    '''def decrypt(self, encrypt_data):

        decrypted_data = self.f.decrypt(encrypt_data.decode())
        return decrypted_data'''

        

    def log(self, log):

#will use at some ponint
        time = datetime.datetime.now()
        with open("scan_log.txt", "ab") as log_file:
            #log_file.write(f"{time} - {log}\n")
            #log_file.write(f"Time of scan: {time} ---  Target IP: {self.target_ip}\n")
            #enc = self.encrypt(log)
            enc = EncDec.EncryptDecrypt("LogKey.key")
            newLog = f"time of scan: {time} target IP: {self.target_ip}  log: {log}"
            log_bytes = newLog.encode("utf-8") #encode the string to bytes
            enc_log = enc.encrypt_(log_bytes)
            log_file.write(enc_log) #encrypted the statsu of the ports to log onto txt file
            log_file.write(b"--END--") #help from stack overflow //new updated lines
    
    
    def TCPscan(self):
        for port in self.target_ports:

            Packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S") #creating a packt with dst ip and port and flag set to SYN
            response = sr1(Packet, timeout=1, verbose=0)  # sr1==function to send a packet and receive a response
            if response is None:
                #print(f"Port {port} is filtered")
                #self.log(response)
                result = f"Port {port} is filtered"
                print(result)
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:#0x12 (18) == flag for SYN/ACK
                    #ACK RST flag will be sent to complete 3 way handhake
                    sr(IP(dst=self.target_ip)/TCP(dport=port, flags="A"), timeout=1, verbose=0)
                    sr(IP(dst=self.target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                    #print(f"Port {port} is open")
                    #self.log(f"Port {port} is open")
                    result = f"Port {port} is open"
                    print(result)
                elif response.getlayer(TCP).flags == 0x14: #0x14 (20) == flag for RST
                    #print(f"Port {port} is closed")
                    #self.log(f"Port {port} is closed")
                    result = f"Port {port} is closed"
                    print(result)
            elif response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [0, 1, 2, 3, 9, 10, 13]:
                    #print(f"Port {port} is filtered")
                    #self.log(f"Port {port} is filtered")
                    result = f"Port {port} is filtered"
                    print(result)

            self.Results.append(result) #puts results into an array
        return self.Results #returns the array so it can be accesed by GUI
    

    def UDPscan(self):
        for port in self.target_ports:
            packet = IP(dst=self.target_ip)/UDP(dport=port)
            response = sr1(packet, timeout=1, verbose=0)  

            if response is None: #if there is no response host might just be ignoring the packet
                result = f"Port {port} is open|filtered"

            elif response.haslayer(UDP): #any response at all == open
                result = f"Port {port} is open"

            elif response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [0, 1, 2, 9, 10, 13]: #icmp typ 3 = destination unreachable 
                    result = f"Port {port} is filtered"

                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3: #closed port/ nmap table showed that code 3 is closed
                    result = f"Port {port} is closed"

            self.Results.append(result)
        #print(self.Results)
        return self.Results
    

    def SYNscan(self):
        for port in self.target_ports:

            packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)  

            if response is None:
                result = f"Port {port} is filtered"

            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12: #0x12 (18) == flag for SYN/ACK
                    sr(IP(dst=self.target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0) #closes the connection so it doesnt complete 3 way hanshake
                    result = f"Port {port} is open"


                elif response.getlayer(TCP).flags == 0x14: #0x14 (20) == flag for RST
                    result = f"Port {port} is closed"

            elif response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [0, 1, 2, 3, 9, 10, 13]: #icmp typ 3 = destination unreachable 
                    result = f"Port {port} is filtered"

            self.Results.append(result) 
        return self.Results
    

    def FINscan(self):
        for port in self.target_ports:
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags="F")
            response = sr1(packet, timeout=1, verbose=0)

            if response is None:
                result = f"Port {port} is open|filtered"

            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14: #0x14 (20) == flag for RST closes the connection 
                    result = f"Port {port} is closed" 

            elif response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]: 
                    result = f"Port {port} is filtered"

            self.Results.append(result) 
        return self.Results
    
    def XMASscan(self):
        for port in self.target_ports:
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags="FPU")
            response = sr1(packet, timeout=1, verbose=0)

            if response is None:
               
                result = f"Port {port} is open|filtered"
               

            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14: #0x14 (20) == flag for RST closes the connection
                    result = f"Port {port} is closed"

            elif response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                    result = f"Port {port} is filtered"

            self.Results.append(result) 
        return self.Results
    


    def Nullscan(self):
        for port in self.target_ports:
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags="")
            response = sr1(packet, timeout=1, verbose=0)

            if response is None:
                result = f"Port {port} is open|filtered"

            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:
                    result = f"Port {port} is closed"

            elif response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                    result = f"Port {port} is filtered"

            self.Results.append(result)
        return self.Results
        

if __name__ == "__main__":
    target_ip = ""  
    target_port = [21 ,53, 67, 68, 123, 161, 162]
    
    target_ports = []

    target_IP = input("Enter the target IP: ")
    ports_input = input("Enter the target ports (comma-separated): ")

    for port in ports_input.split(","):
        target_ports.append(int(port.strip()))


    # Create an instance of the Port_Scanner class
    
    scanner = Port_Scanner(target_IP, target_ports)
    scanner.TCPscan()
    save = input("Do you want to save the results? (y/n): ")
    if save.lower() == "y":
        scanner.log(scanner.Results)



    display = input("Do you want to display the decrypted results? (y/n): ")
    if display.lower() == "y":
        with open("scan_log.txt", "r") as log_file:
            for line in log_file:
                if line.strip():
                    decrypted_line = scanner.decrypt(line.strip())
                    print(decrypted_line)
    


    
    # Perform the scan
    #scanner.UDPscan()