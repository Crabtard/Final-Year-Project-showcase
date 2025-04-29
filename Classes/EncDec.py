from cryptography.fernet import Fernet

#Thius is to encrypt and decrypt data
#generates a key saves to file for future use if one is not found
class EncryptDecrypt:
    def __init__(self, key_file):
        self.key_file = key_file
      

        try:
            with open(self.key_file, "r") as key_file:
                self.key = key_file.read()
                #print("Key exists. Using existing key.")
        except FileNotFoundError:
            #print("Key file not found. Creating new key.")
            self.key = Fernet.generate_key()
            with open(self.key_file, 'w') as key_file:
                key_file.write(self.key)
                #print("New key created and saved.")


        self.f = Fernet(self.key)


    def encrypt_(self, data):
        #f = Fernet(self.key)
        encrypted_data = self.f.encrypt(data)
        return encrypted_data
    

    def decrypt_(self, encrypted_data):
        #f = Fernet(self.key)
        decrypted_data = self.f.decrypt(encrypted_data)
        return decrypted_data
                

if __name__ == "__main__":
    #ed = EncryptDecrypt("mykey.key")
    #enc = ed.encrypt("hello world")
    #print("Encrypted:", enc)
    #dec = ed.decrypt(enc)
    #print("Decrypted:", dec)

    ed = EncryptDecrypt("LogKey.key")

    file = open("scan_log.txt", "r")
    lines = file.readlines()
    for line in lines:
        print("Line:", line)
        try:
            dec = ed.decrypt_(line.strip())
            print("Decrypted:", dec)
        except Exception as e:
            print("Error decrypting line:", e)

        
            

    