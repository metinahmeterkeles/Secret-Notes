import tkinter
from typing import Type

from PIL import Image, ImageTk
import base64
from tkinter import messagebox, Message

window = tkinter.Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)


def encyrpt_button_clicked():
    secret = secret_txt.get("1.0", tkinter.END)
    master = masterkey_entry.get()
    title = title_entry.get()

    if secret == "" or master == "":
        messagebox.showinfo("Error", "Please enter all information")

    else:
        #encryption
        message_encryption = encode(master,secret)

        with open("mysecret.txt","a") as data_file:
            data_file.write(f"\n{title}\n{message_encryption}")

        secret_txt.delete(1.0, tkinter.END)
        masterkey_entry.delete(0,tkinter.END)
        title_entry.delete(0,tkinter.END)


def decyrpt_button_clicked():
    secret = secret_txt.get("1.0", tkinter.END)
    master = masterkey_entry.get()
    title = title_entry.get()

    if secret == "" or master == "":
        messagebox.showinfo("Error", "Please enter all information")

    else:
        try:
            message_decryption = decode(master,secret)
            secret_txt.delete(1.0,tkinter.END)
            masterkey_entry.delete(0,tkinter.END)
            title_entry.delete(0, tkinter.END)
            secret_txt.insert("1.0",message_decryption)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)

        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, message):
    dec = []
    message = base64.urlsafe_b64decode(message).decode()

    for i in range(len(message)):
        key_c = key[i % len(key)]
        dec.append(chr((256 + ord(message[i]) - ord(key_c)) % 256))

    return "".join(dec)


frame = tkinter.Frame(window)
frame.pack()
img = ImageTk.PhotoImage(Image.open("topsecret.png"))
label = tkinter.Label(frame, image=img)
label.pack()

title_label = tkinter.Label(text="Enter your title")
title_label.pack()

title_entry = tkinter.Entry()
title_entry.pack()

secret_label = tkinter.Label(text="Enter your secret")
secret_label.pack()

secret_txt = tkinter.Text(width=30, height=15)
secret_txt.pack()

masterkey_label = tkinter.Label(text="Enter master key")
masterkey_label.pack()

masterkey_entry = tkinter.Entry()
masterkey_entry.pack()

save_encrypt_button = tkinter.Button(text="Save&Encrypt", command=encyrpt_button_clicked)
save_encrypt_button.pack()

decrypt_button = tkinter.Button(text="Decrypt", command=decyrpt_button_clicked)
decrypt_button.pack()

window.mainloop()
