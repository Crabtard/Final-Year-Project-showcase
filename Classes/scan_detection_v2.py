import customtkinter as ctk
from tkinter import messagebox
from scapy.all import *
import threading
import datetime

class ScanDetection(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Scan Detection")
        self.geometry("750x500")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        

        self.ip_label = ctk.CTkLabel(self, text="Enter IP Address")
        self.ip_label.pack(pady=10)

        frm = ctk.CTkFrame(self)
        frm.pack(pady=10)

        self.ip_entry = ctk.CTkEntry(frm, width=300, placeholder_text="IP Address")
        self.ip_entry.pack(pady=5)

        self.hours_entry = ctk.CTkEntry(frm, width=50, placeholder_text="Hours")
        self.hours_entry.pack(pady=5, side="left")

        self.minutes_entry = ctk.CTkEntry(frm, width=50, placeholder_text="Minutes")
        self.minutes_entry.pack(pady=5, side="left")

        self.seconds_entry = ctk.CTkEntry(frm, width=50, placeholder_text="Seconds")
        self.seconds_entry.pack(pady=5, side="left")

        self.start = ctk.CTkButton(frm, text="Start", width=80, command=self.start_sniff)
        self.start.pack(side="right")

        self.display = ctk.CTkScrollableFrame(self)
        self.display.pack(fill="both", expand="true", padx=10, pady=10)

        self.clear = ctk.CTkButton(self, text="Clear", width=80, command=self.clear_output)
        self.clear.pack(pady=10)

        self.Timestart = datetime.datetime.now()

        self.Quitbtn = ctk.CTkButton(self, text="Quit", width=80, command=self.Quit)
        self.Quitbtn.pack(pady=10)

    def Quit(self):
        self.withdraw()
        
        


    def show_output(self, result):
        new_lbl = ctk.CTkLabel(self.display, text=result)
        new_lbl.pack(pady=1)

    def clear_output(self):
        for widget in self.display.winfo_children():
            widget.destroy()
        self.show_output("Output cleared.")

        
    def start_sniff(self):
        #below sets timeout for sniff function, was going to implement a stop button but timeout is prob more useful, so user can just leave it running and get back to it and check if there has been any suspicious activity
        self.hours = self.hours_entry.get()
        self.minutes = self.minutes_entry.get()
        self.seconds = self.seconds_entry.get()
        if self.hours == "" and self.minutes == "" and self.seconds == "":
            messagebox.showerror("Error", "Please enter a time duration.")
            return
        try: #did a try block so it trys converts to int so can be used as timeout and of not valid will show erro message instead of the code stopping
            self.hours = int(self.hours) 
            self.minutes = int(self.minutes)
            self.seconds = int(self.seconds)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid time duration.")
            return
        
        if self.hours < 0 or self.minutes < 0 or self.seconds < 0: #so user cant input negative number
            messagebox.showerror("Error", "Please enter a valid time duration.")
            return
        
        else:
            self.timeout = (self.hours * 3600) + (self.minutes * 60) + self.seconds
      
        self.ip = self.ip_entry.get()
        if self.ip == "":
            messagebox.showerror("Error", "Please enter an IP address.")
            return
        self.start.configure(state="disabled")
        self.show_output(f"Sniffing started at {self.Timestart} for {self.hours} hours, {self.minutes} minutes, and {self.seconds} seconds.")

        def sniffer(pkt):
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dest_ip = pkt[IP].dst
                pktload = pkt[IP].payload

                #print(f"Source IP: {src_ip} | Destination IP: {dest_ip} | Packet Load: {pktload}")
                #results = f"Source IP: {src_ip} | Destination IP: {dest_ip} | Packet Load: {pktload}"
                #self.show_output(results)
               
                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dest_port = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    result = f"TCP Packet: {src_ip} -> {dest_ip} | {src_port} -> {dest_port} | Flags: {flags}"
                    self.show_output(result)
                        
                        
                elif pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dest_port = pkt[UDP].dport
                    result = f"UDP Packet: {src_ip} -> {dest_ip} | {src_port} -> {dest_port}"
                    self.show_output(result)
                        
                elif pkt.haslayer(ICMP):
                    icmp_type = pkt[ICMP].type
                    icmp_code = pkt[ICMP].code
                    result = f"ICMP Packet: {src_ip} -> {dest_ip} | Type: {icmp_type} | Code: {icmp_code}"
                    self.show_output(result)

        

        def detection():
            sniff(filter=f"host {self.ip}", prn=sniffer, store=0, timeout=self.timeout) #do a timeout so sniff stops after specified time
            self.TimeEnd = datetime.datetime.now()
            self.show_output(f"Sniffing stopped at {self.TimeEnd}")
            self.start.configure(state="normal")


        self.thread1 = threading.Thread(target=detection) #creared a thread beacuse when using the sniff function it stops everything else from runnig, so put it into its own thread so GUI can run whilst the sniff function is running
        self.thread1.start()

    
        



    



if __name__ == "__main__":
    root = ScanDetection()
    root.mainloop()
