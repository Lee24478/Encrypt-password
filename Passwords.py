# import base64
# import os
# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptocode
import msvcrt
import os

def pwd_input():
    chars = []
    while True:
        try:
            newChar = msvcrt.getch().decode(encoding = "utf-8")
        except:
            return input("(不在cmd命令下執行,密碼輸入將不能隱藏)")
        
        if newChar in '\r\n': #換行就break #Press Enter
            break
        elif newChar == '\b': #退一格 #Press Backend 
            if chars:
                del chars[-1]  #chars.pop()
                msvcrt.putch('\b'.encode(encoding = "utf-8"))
                msvcrt.putch(' '.encode(encoding = "utf-8"))
                msvcrt.putch('\b'.encode(encoding = "utf-8"))
        else:
            chars.append(newChar)
            msvcrt.putch('*'.encode(encoding = "utf-8"))
        #os.system("pause")
    return ''.join(chars)

# Master_key = input("Master_key : ")
# Confirm_key = cryptocode.encrypt(Master_key , Master_key)

""" 
#####Generate key#####
def generate_key():
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000
    )
    key = base64.urlsafe_b64encode(kdf.derive(Master_key))
    #key = Fernet.generate_key()
    with open("Key.key" , 'wb') as k:
        k.write(key)

generate_key()  
"""
""" 
def load_key():
    with open("Key.key" , 'rb') as k:
        key = k.read()
    return key

key = load_key() 
f = Fernet(key)
"""

def add(Master_key):
    Account_name = input("Account name : ")
    # Password = input("Password : ")
    print("Password : " , end = '' , flush = True)
    Password = pwd_input()
    print()
    token = cryptocode.encrypt(Password , Master_key)
    with open("Password.txt" , 'a') as a:
        a.write(Account_name + ' | ' + token + '\n')
    print("Successfully Add!")

def view(Master_key):
    try:
        with open("Password.txt" , 'r') as r:
            for line in r.readlines():
                line = line.strip()
                Account_name , Password = line.split(' | ')
                Decrypt_password = cryptocode.decrypt(Password , Master_key)
                if Decrypt_password:
                    print("Account name :" , Account_name , "|" , "Password :" , Decrypt_password)
                else:
                    print("[Wrong Key]:Access deny!")
    except:
        print("Please 'Add' account first , you don't have file to view!")

def edit(Master_key):
    Account_list = []
    Decrypt_password_list = []
    try:
        with open("Password.txt" , 'r') as r:
            lines = r.readlines()
            for line in lines:
                line = line.strip()
                Account_name , Password = line.split(' | ')
                Account_list.append(Account_name)
                Decrypt_password = cryptocode.decrypt(Password , Master_key)
                Decrypt_password_list.append(Decrypt_password)
    except:
        print("Please 'Add' account first , you don't have file to edit!")
        return 

    while True:
        print("Your current account list :" , Account_list)
        edit_word = input("Which account's password do you want to edit?(Case sensitive) ").strip()
        if edit_word not in Account_list:
            print("[Error]:You don't have this account.")
            continue
        else:
            Check_index = Account_list.index(edit_word)
            if Decrypt_password_list[Check_index]:
                while True:
                    # edit_password = input("Type new password : ")
                    # confirm_password = input("Type new password again to confirm : ")
                    print("Type new password : " , end = '' , flush = True)
                    edit_password = pwd_input()
                    print()
                    print("Type new password again to confirm : " , end = '' , flush = True)
                    confirm_password = pwd_input()
                    print()
                    if edit_password == confirm_password:
                        with open("Password.txt" , 'w') as w:
                            for line in lines:
                                if edit_word not in line.strip():
                                    w.write(line)
                                else:
                                    w.write(edit_word + " | " + cryptocode.encrypt(edit_password , Master_key) + '\n')
                                    print("Successfully edit!")
                        break
                    else:
                        print("[Error]:Please make sure you type new password correctly twice!")
                        continue
                break
            else:
                print("[Wrong Key]:Access deny , You don't have an authority to edit this account!")
                break

def delete(Master_key):
    Account_list = []
    Decrypt_password_list = []
    try:
        with open("Password.txt" , 'r') as r:
            lines = r.readlines()
            for line in lines:
                line = line.strip()
                Account_name , Password = line.split(' | ')
                Account_list.append(Account_name)
                Decrypt_password = cryptocode.decrypt(Password , Master_key)
                Decrypt_password_list.append(Decrypt_password)
    except:
        print("Please 'Add' account first , you don't have file to delete!")
        return

    while True:
        print("Your current account list :" , Account_list)
        del_word = input("Which account do you want to delete?(Case sensitive) ").strip()
        if del_word not in Account_list:
            print("[Error]:You don't have this account.")
            continue
        else:
            Check_index = Account_list.index(del_word)
            if Decrypt_password_list[Check_index]:
                with open("Password.txt" , 'w') as w:
                    for line in lines:
                        if del_word not in line.strip():
                            w.write(line)
                        else:
                            print("Successfully delete!")
                break
            else:
                print("[Wrong Key]:Access deny , You don't have an authority to delete this account!")
                break

def main():
    print("Master Key : " , end = '' , flush = True)
    Master_key = pwd_input()
    print()
    # Master_key = input("Master_key : ")
    while True:
        answer = input("'Add' , 'View' , 'Edit' or 'Delete' passwords? (type c to change Master key)(type q to quit) : ").lower()
        if answer == "q":
            break
        elif answer == "add":
            add(Master_key)
        elif answer == "view":
            view(Master_key)
        elif answer == "edit":
            edit(Master_key)
        elif answer == "delete":
            delete(Master_key)
        elif answer == "c":
            # global Master_key
            # Master_key = input("Master_key : ")
            print("Master Key : " , end = '' , flush = True)
            Master_key = pwd_input()
            print()
        else:
            print("[Error]:Invalid input!")
            continue

if __name__ == "__main__":  #To make sure we run this function in this main file , if accidentally run this function in other file , it won't implement
    main()
