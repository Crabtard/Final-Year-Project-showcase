#trying to add threading to main

import sys
import customtkinter as ctk

from tkinter import messagebox

import threading


#importing the different pyfiles
import PortScanner
import scan_detection_v2
import EncDec



ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        

        self.title("Port Scanner")
        self.geometry("600x600")
        self.resizable(False, False)

        self.Welcome = ctk.CTkLabel(master=self, text="Welcome")
        self.OPT_frm = ctk.CTkFrame(master=self, width=100, height=600)
        #self.scan_frm = ctk.CTkFrame(master=self, width=600, height=600)


        self.OPT_frm.pack(side="left", padx=10, pady=10)

        #each options button --------------------------------
        home = ctk.CTkButton(master=self.OPT_frm, text="Home", corner_radius=0, hover_color="dark grey", command=self.Home)
        home.pack()

        New_scan = ctk.CTkButton(master=self.OPT_frm, text="New Scan", corner_radius=0, hover_color="dark grey", command=self.new_scan)#REPLACE WITH FUNCTION TO OPEN NEW SCAN FRAME
        New_scan.pack()

        settings = ctk.CTkButton(master=self.OPT_frm, text="Settings", corner_radius=0, hover_color="dark grey", command=self.Settings)#REPLACE WITH FUNCTION TO OPEN SETTINGS FRAME
        settings.pack()

        history = ctk.CTkButton(master=self.OPT_frm, text="History", corner_radius=0, hover_color="dark grey", command=self.history)
        history.pack()

        self.scan_detectionbtn = ctk.CTkButton(master=self.OPT_frm, text="Scan Detection", corner_radius=0, hover_color="dark grey", command=self.scan_detection)
        self.scan_detectionbtn.pack()

        self.Exit = ctk.CTkButton(master=self.OPT_frm, text="Exit", corner_radius=0, hover_color="dark grey", command=sys.exit)
        self.Exit.pack()

        self.info = ctk.CTkLabel(master=self, text_color="black", fg_color="white", text="Click on the buttons to navigate to the different options.\n" 
        "To do a scan, click on New Scan and enter the target IP and ports.\n" 
        "To view the scan history, click on History.\n" 
        "To change the settings, click on Settings.\n" 
        "To do a detect a scan, click on Scan Detection.\n")
    


    def Home(self):
        #closes the scan frame and history frame if they are open
      
        #self.scan_frm.pack_forget()
            #self.hst_frm.pack_forget()
        
        
        self.configure(fg_color="teal")
      
        self.Welcome.pack(anchor="center", pady=10)

        #options frame
        
        self.OPT_frm.pack(side="left", padx=10, pady=10)
        self.OPT_frm.pack_propagate(False)

        self.info.pack(side="top", padx=10, pady=10)
      

        #moved to init because when the home button was pressed it kept adding more buttons to the frame
        '''#each options button --------------------------------
        home = ctk.CTkButton(master=self.OPT_frm, text="Home", corner_radius=0, hover_color="dark grey", command=self.Home)
        home.pack()

        New_scan = ctk.CTkButton(master=self.OPT_frm, text="New Scan", corner_radius=0, hover_color="dark grey", command=self.new_scan)#REPLACE WITH FUNCTION TO OPEN NEW SCAN FRAME
        New_scan.pack()

        settings = ctk.CTkButton(master=self.OPT_frm, text="Settings", corner_radius=0, hover_color="dark grey", command=self.Settings)#REPLACE WITH FUNCTION TO OPEN SETTINGS FRAME
        settings.pack()

        history = ctk.CTkButton(master=self.OPT_frm, text="History", corner_radius=0, hover_color="dark grey")
        history.pack()'''
    
    def new_scan(self):

      
        
        self.ports = []
        
        #self.scan_frm.pack_forget()
        self.scan_frm = ctk.CTkFrame(master=self, width=600, height=600)

        self.info.pack_forget()
        self.Welcome.pack_forget()
        #self.scan_frm = ctk.CTkFrame(master=self, width=500, height=600)
        self.OPT_frm.pack_forget()
        self.scan_frm.pack(side="right", padx=10, pady=10)
        self.scan_frm.pack_propagate(False)

        info_lbl = ctk.CTkLabel(master=self.scan_frm, text="Enter Target IP and \n Target ports (with commas in between)")
        info_lbl.pack(anchor="center")



        IP_input = ctk.CTkEntry(master=self.scan_frm, placeholder_text="Input Target IP", text_color="light green")
        IP_input.pack(anchor="center", pady=2)



        Ports_input = ctk.CTkEntry(master=self.scan_frm, placeholder_text="Input Target Ports", text_color="light green", state="disabled")
        Ports_input.pack(anchor="center", pady=2)
        
        #gets ip and port input
        self.ip = ""
        #self.input_port = Ports_input.get()
        #Ports_input.pack(anchor="center", pady=10)
        def select(value): #here it makes it so user has choice to input ports or use the ones that are already there
            self.ports.clear()
            if value == "Select your own ports":
                self.ports.clear()
                Ports_input.configure(state="normal", placeholder_text="Input Target Ports")
            elif value == "first 1024 ports":
                Ports_input.configure(state="disabled")  
                for i in range(0, 1024):
                    self.ports.append(i)

            elif value == "All ports":
                Ports_input.configure(state="disabled")
                for i in range(0, 65535):
                    self.ports.append(i)
                    
            
            elif value == "common TCP ports":
                Ports_input.configure(state="disabled")
                common_tcp_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306] 
                for i in common_tcp_ports:
                    self.ports.append(i)
                    
            elif value == "Common UDP ports":
                Ports_input.configure(state="disabled")
                common_udp_ports = [53, 67, 68, 123, 161, 162] 
                for i in common_udp_ports:
                    self.ports.append(i)
            else:
                Ports_input.configure(state="disabled")
                print(f"Selected: {value}")
        newcombobox = ctk.CTkComboBox(master=self.scan_frm, values=["common TCP ports", "Common UDP ports", "first 1024 ports", "All ports", "Select your own ports"],  dropdown_hover_color="dark grey", command=select)
        newcombobox.pack()
        newcombobox.set("--choose option--")
            
        

        lbl = ctk.CTkLabel(master=self.scan_frm, text="")
       

        def confirm():
            #self.ports.clear() #added this to clear the ports list so it doesn't keep adding more when pressing confirm btn
            #self.ports = []
            
            self.ip = IP_input.get()
            self.input_port = Ports_input.get()

            #if self.ip == None: #change to this if below doesn't work
            if self.ip == "": #no ip entered == error popup
                messagebox.showerror("Error", "Please enter an ip address")

            else: #if no number is entered == error message popup
                #if self.ip !=  None: #removed -- bring back if errors occur :/

                    
                    '''for i in self.input_port.split(","): #removes commas from input
                        if i != int:
                            messagebox.showerror("Error", "Please enter a valid port number(s)")'''

            
                    if newcombobox.get() == "Select your own ports": #if user selects their own ports //remove if not working
                        for port in self.input_port.split(","):
                            try: #this try catch trries to see if the input is a number and if not it will skip it / did ths so if user inputs a string it doesn't crash the code
                                self.ports.append(int(port.strip()))
                            except ValueError:
                                print("skipping invalid port")
                                messagebox.showerror("Error", "Please enter a valid port number(s)")

                    elif len(self.ports) == 0:
                            messagebox.showerror("Error", "Please enter a valid port number(s)")

                        

                    for i in self.ports:
                        if i < 0 or i > 65535:
                            messagebox.showerror("Error", "Please enter a valid port number(s)")
                            self.ports.clear()

                        #elif len(self.ports) == 0:
                         #   messagebox.showerror("Error", "Please enter a valid port number(s)")

                      
                
            lbl.configure(text=f"Target IP: {self.ip}\nTarget Ports: {self.ports}")
        
        confirm_btn = ctk.CTkButton(master=self.scan_frm, text="Confirm",  hover_color="dark grey", command=confirm)
        confirm_btn.pack(anchor="center", pady=5)
        lbl.pack(anchor="center", pady=2)
      
#scan choice/scan type/results frame
        self.results_frm = ctk.CTkScrollableFrame(master=self.scan_frm, width=200, height=200, fg_color="lime green") 
        
        def scan_choice(value):
            scan_type = scan_choicebox.get()

            def shw_results(result):#func to show results on frm
                display = "\n".join(result)#help from stack overflow --- this displays the results in a readable format -- .join makes resuts array into string amd \n splits each result omto a new line 🔥
                
                self.scan_result = display #this holds results so i can access it when saving results
                new_lbl = ctk.CTkLabel(master=self.results_frm, text=display, text_color="black")
                new_lbl.pack(side="top", pady=5)

            def perform_scan():
            
                if scan_type == "TCP":
                    TCPScan = PortScanner.Port_Scanner(self.ip, self.ports)
                    scan_complete = TCPScan.TCPscan()
                    
                    self.results = ctk.CTkLabel(master=self.results_frm, text="Scan Results --- TCP", text_color="black")
                    self.results.pack(side="top", pady=10)
                    
                    shw_results(scan_complete) 

                    #make save button and use log function from PortScanner.py to save the results to a file
                elif scan_type == "UDP":
                    UDPScan = PortScanner.Port_Scanner(self.ip, self.ports)
                    scan_complete = UDPScan.UDPscan()
                    
                    self.results = ctk.CTkLabel(master=self.results_frm, text="Scan Results --- UDP", text_color="black")
                    self.results.pack(side="top", pady=10)
                    
                    shw_results(scan_complete)


                elif scan_type == "SYN":
                    SYNScan = PortScanner.Port_Scanner(self.ip, self.ports)
                    scan_complete = SYNScan.SYNscan()
                    
                    self.results = ctk.CTkLabel(master=self.results_frm, text="Scan Results --- SYN", text_color="black")
                    self.results.pack(side="top", pady=10)
                    
                    shw_results(scan_complete)
                    
                elif scan_type == "FIN":
                    FINScan = PortScanner.Port_Scanner(self.ip, self.ports)
                    scan_complete = FINScan.FINscan()
                    
                    self.results = ctk.CTkLabel(master=self.results_frm, text="Scan Results --- FIN", text_color="black")
                    self.results.pack(side="top", pady=10)

                    shw_results(scan_complete)

                elif scan_type == "XMAS":
                    XMASScan = PortScanner.Port_Scanner(self.ip, self.ports)
                    scan_complete = XMASScan.XMASscan()
                    
                    self.results = ctk.CTkLabel(master=self.results_frm, text="Scan Results --- XMAS", text_color="black")
                    self.results.pack(side="top", pady=10)
                    
                    shw_results(scan_complete)

                elif scan_type == "Null":
                    NullScan = PortScanner.Port_Scanner(self.ip, self.ports)
                    scan_complete = NullScan.Nullscan()
                    
                    self.results = ctk.CTkLabel(master=self.results_frm, text="Scan Results --- Null", text_color="black")
                    self.results.pack(side="top", pady=10)
                    
                    shw_results(scan_complete)

            thread1 = threading.Thread(target=perform_scan) #threading so gui doesn't freeze when scan is running
            thread1.start()

            

        scan_choicebox = ctk.CTkComboBox(master=self.scan_frm, state="readonly", values=["TCP", "UDP", "SYN", "FIN", "XMAS", "Null"], dropdown_hover_color="dark grey", text_color="light green", command=scan_choice)
        scan_choicebox.set("---Select Scan Type---")
        scan_choicebox.pack(anchor="center", pady=10)

        
        self.results_frm.pack(anchor="center", pady=10)
        #---- clear results button------------------
        def clear_results():
            for widget in self.results_frm.winfo_children():
                widget.destroy()
            messagebox.showinfo("Info", "Results cleared")

        clearbtn = ctk.CTkButton(master=self.scan_frm, text="Clear Results", hover_color="dark grey", command=clear_results)
        clearbtn.pack(anchor="center", pady=5)

        #--save results button------------------
        def save_results():
            Log = PortScanner.Port_Scanner(self.ip, self.ports)
            #Log.log(self.scan_result.cget("text")) #cget takes text from label -- help from geeksforgeeks
            Log.log(self.scan_result) 
            messagebox.showinfo("Info", "Results saved to scan_log.txt")

        save_btn = ctk.CTkButton(master=self.scan_frm, text="Save Results", hover_color="dark grey", command=save_results)
        save_btn.pack(anchor="center", pady=5)

        def back():
            messagebox.showinfo("Info", "Going back to home, all unsaved data will be lost")
            self.scan_frm.pack_forget()
            self.Home()

        back_btn = ctk.CTkButton(master=self.scan_frm, text="Back", hover_color="dark grey", command=back)
        back_btn.pack(anchor="center", pady=5)
        
        

    

            

    def Settings(self):
        settings = ctk.CTkToplevel(root)
        settings.title("Settings")
        settings.geometry("400x200")
        settings.resizable(False, False)


        scroll_frm = ctk.CTkScrollableFrame(master=settings, bg_color="dark grey")
        scroll_frm.pack(expand=True, fill="both")

        settings_lbl = ctk.CTkLabel(master=scroll_frm, text="Settings")
        settings_lbl.pack(side="top", pady=10)
        
        #-----Theme-----------------------------------------
        def theme_change(value):
            if value == "Dark":
                ctk.set_appearance_mode("dark")
                self.configure(fg_color="teal")

            else:
                ctk.set_appearance_mode("light")
                self.configure(fg_color="sea green")
                
                
        theme_lbl = ctk.CTkLabel(master=scroll_frm, text="Select Theme")
        theme_lbl.pack(side="left", pady=10)

        theme_cb = ctk.CTkComboBox(master=scroll_frm, state="readonly", values=["Dark", "Light"], dropdown_hover_color="dark grey", command=theme_change)
        theme_cb.set("Dark")
        theme_cb.pack(side="left", pady=10)

        #change font size -------------------
        

        
        settings.mainloop()
    def scan_detection(self):

        self.scandection = scan_detection_v2.ScanDetection()
        self.scandection.mainloop()


         

        
    def history(self):
            hst = ctk.CTkToplevel(root)
            hst.title("History")
            hst.geometry("800x600") 
            hst.resizable(False, False)
            scroll_frm1 = ctk.CTkScrollableFrame(master=hst, bg_color="dark grey")
            scroll_frm1.pack(expand=True, fill="both")

            hst_lbl = ctk.CTkLabel(master=scroll_frm1, text="Scan History -- Encrypted", text_color="lime green")
            hst_lbl.pack(anchor="n", pady=10)
 
            def display():
               
                def decryptLog():
                    with open("scan_log.txt", "r") as read_file:
                        encdec = EncDec.EncryptDecrypt("LogKey.key")
                        lines = read_file.read()
                        logs_list = lines.split("--END--")
                        for line in logs_list:
                            if line:
                                dec_data = encdec.decrypt_(bytes(line, encoding="utf-8"))
                                hst_lbl2 = ctk.CTkLabel(master=scroll_frm1, text=dec_data, text_color="red")
                                hst_lbl2.pack(anchor="center", pady=10)
                                display_enc.configure(state="disabled") #IT WORKSSSSS // help from https://stackoverflow.com/questions/66791227/why-am-i-getting-cryptography-fernet-invalidtoken-when-using-the-same-key
                    
                thread2 = threading.Thread(target=decryptLog)
                thread2.start()
            display_enc = ctk.CTkButton(master=scroll_frm1, text="Display  Scan History", command=display, hover_color="dark grey")
            display_enc.pack(anchor="center", pady=10)
           
            hst.mainloop()
                    
   
    
if __name__ == "__main__":
    root = App()
    root.Home()
    root.mainloop()


        