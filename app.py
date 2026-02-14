import os
import json
import base64
import glob
import tkinter as tk
from tkinter import messagebox
from Users import Users
from Encryption import Encryption
from Decryption import Decryption
from Signature import Signature
import atexit


#Configuration
RSA_BITS_DEFAULT = 3072
PACKET_A_TO_B = "packet_Sender_to_Recipient.json"
PACKET_B_TO_A = "packet_Recipient_to_Sender.json"
CHAT_LOG = "chat_log.txt"
DECRYPT_OUT = "decryption_output.txt"


# helper Functions
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def save_json(filename: str, obj):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def load_json(filename: str):
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)


# GUI & Application
class SecureChatApp:
    def __init__(self, root):
        self.root = root
        root.title("Secure Chat Application")
        root.geometry("1100x760")
        root.configure(bg="white")

        # Users
        self.sender = Users("Sender")
        self.recipient = Users("Recipient")
        self.sender.load_keys_if_exist()
        self.recipient.load_keys_if_exist()

        self.chat_history = []

        top = tk.Frame(root, bg="white")
        top.pack(pady=8)

        tk.Label(top, text="RSA bits:", bg="white",
                 font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5)

        self.bits_var = tk.IntVar(value=RSA_BITS_DEFAULT)
        bits_box = tk.OptionMenu(top, self.bits_var, 1024, 2048, 3072)
        bits_box.grid(row=0, column=1, padx=5)

        tk.Button(top, text="Generate Keys", bg="#4CAF50", fg="white",
                  font=("Arial", 11, "bold"),
                  command=self.generate_keys).grid(row=0, column=2, padx=8)

        tk.Button(top, text="Auto-Load Keys", bg="#4CAF50", fg="white",
                  font=("Arial", 11, "bold"),
                  command=self.autoload_keys).grid(row=0, column=3, padx=8)

        tk.Button(top, text="Reset All", bg="#D9534F", fg="white",
                  font=("Arial", 11, "bold"),
                  command=self.reset_all).grid(row=0, column=4, padx=8)

        #MAIN LAYOUT
        main = tk.Frame(root, bg="white")
        main.pack(fill="both", expand=True, padx=10, pady=10)
        entry_width = 76

        # SENDER PANEL
        sender_frame = tk.LabelFrame(main, text="Sender", bg="white", font=("Arial", 12, "bold"), padx=8, pady=8)
        sender_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        main.grid_columnconfigure(0, weight=1)

        tk.Label(sender_frame, text="Chat Log:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")

        self.sender_chat_log = tk.Text(sender_frame, width=entry_width, height=12, font=("Consolas", 10), bd=2, relief="solid", state="disabled")
        self.sender_chat_log.pack(pady=4)

        tk.Label(sender_frame, text="Type a message:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")

        self.sender_input = tk.Text(sender_frame, width=entry_width, height=3, font=("Consolas", 10), bd=2, relief="solid")
        self.sender_input.pack(pady=4)

        tk.Button(sender_frame, text="Send to Recipient", bg="#4CAF50", fg="white", font=("Arial", 11, "bold"), command=self.sender_send).pack(pady=5)

        tk.Button(sender_frame, text="Decrypt Recipient's Message", bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), command=self.receive_for_sender).pack(pady=5)

        # PACKET VIEW PANEL
        pkt_frame = tk.LabelFrame(main, text="Packet (transmitted)", bg="white", font=("Arial", 12, "bold"), padx=8, pady=8)
        pkt_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        main.grid_columnconfigure(1, weight=1)

        tk.Label(pkt_frame, text="Encrypted AES Key:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")
        self.p_enc_key = tk.Text(pkt_frame, width=entry_width, height=3, font=("Consolas", 9), bd=2, relief="solid")
        self.p_enc_key.pack(pady=3)

        tk.Label(pkt_frame, text="Nonce:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")
        self.p_nonce = tk.Entry(pkt_frame, width=90, font=("Consolas", 9), bd=2, relief="solid")
        self.p_nonce.pack(pady=3)

        tk.Label(pkt_frame, text="Ciphertext:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")
        self.p_cipher = tk.Text(pkt_frame, width=entry_width, height=4, font=("Consolas", 9), bd=2, relief="solid")
        self.p_cipher.pack(pady=3)

        tk.Label(pkt_frame, text="Tag:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")
        self.p_tag = tk.Entry(pkt_frame, width=90, font=("Consolas", 9), bd=2, relief="solid")
        self.p_tag.pack(pady=3)

        tk.Label(pkt_frame, text="Signature:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")
        self.p_sig = tk.Text(pkt_frame, width=entry_width, height=4, font=("Consolas", 9), bd=2, relief="solid")
        self.p_sig.pack(pady=3)

        # RECIPIENT PANEL
        recipient_frame = tk.LabelFrame(main, text="Recipient", bg="white", font=("Arial", 12, "bold"), padx=8, pady=8)
        recipient_frame.grid(row=0, column=2, sticky="nsew", padx=5)
        main.grid_columnconfigure(2, weight=1)

        tk.Label(recipient_frame, text="Chat Log:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")

        self.recipient_chat_log = tk.Text(recipient_frame, width=entry_width, height=12, font=("Consolas", 10), bd=2, relief="solid", state="disabled")
        self.recipient_chat_log.pack(pady=4)

        tk.Label(recipient_frame, text="Type a message:", bg="white", font=("Arial", 10, "bold")).pack(anchor="w")

        self.recipient_input = tk.Text(recipient_frame, width=entry_width, height=3, font=("Consolas", 10), bd=2, relief="solid")
        self.recipient_input.pack(pady=4)

        tk.Button(recipient_frame, text="Send to Sender", bg="#4CAF50", fg="white", font=("Arial", 11, "bold"), command=self.recipient_send).pack(pady=5)

        tk.Button(recipient_frame, text="Decrypt Sender's Message", bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), command=self.receive_for_recipient).pack(pady=5)

        #Output
        out_frame = tk.Frame(root, bg="white")
        out_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(out_frame, text="Log/ Status", bg="white", font=("Arial", 11, "bold")).pack(anchor="w")

        self.output = tk.Text(out_frame, width=140, height=8, font=("Consolas", 10), bd=2, relief="solid")
        self.output.pack(pady=6)

    # KEY CONTROLS
    def generate_keys(self):
        bits = int(self.bits_var.get())
        self.sender.generate_keys(bits)
        self.recipient.generate_keys(bits)
        messagebox.showinfo("Keys Generated", "All RSA keypairs were generated successfully.")

    def autoload_keys(self):
        self.sender.load_keys_if_exist()
        self.recipient.load_keys_if_exist()
        messagebox.showinfo("Keys Loaded", "Loaded keypairs from files (if available).")

    #RESET_ALL
    def reset_all(self):
        delete_files = [
            "Sender_enc_private.pem", "Sender_enc_public.pem",
            "Sender_sig_private.pem", "Sender_sig_public.pem",
            "Recipient_enc_private.pem", "Recipient_enc_public.pem",
            "Recipient_sig_private.pem", "Recipient_sig_public.pem",
            PACKET_A_TO_B, PACKET_B_TO_A, CHAT_LOG, DECRYPT_OUT
        ]

        for f in delete_files:
            if os.path.exists(f):
                try: os.remove(f)
                except: pass

        self.sender = Users("Sender")
        self.recipient = Users("Recipient")
        self.chat_history = []

        for box in   [self.sender_chat_log, self.recipient_chat_log,
                    self.sender_input, self.recipient_input,
                    self.p_enc_key, self.p_cipher, self.p_sig,
                    self.output]:
            box.config(state="normal")
            box.delete("1.0", tk.END)
            if box in [self.sender_chat_log, self.recipient_chat_log]:
                box.config(state="disabled")

        self.p_nonce.delete(0, tk.END)
        self.p_tag.delete(0, tk.END)

        messagebox.showinfo("Reset Complete", "All keys, packets, logs and fields were cleared.")

    # Encrypted message SENDER → RECIPIENT
    def sender_send(self):
        msg = self.sender_input.get("1.0", tk.END).strip()
        if not msg:
            return messagebox.showwarning("Empty", "Sender typed nothing.")

        if not (self.sender.has_keys() and self.recipient.has_keys()):
            return messagebox.showerror("Missing Keys", "Keys not generated or loaded.")
        
        # providing public key and msg
        enc = Encryption(self.recipient.enc_pub_obj)
        enc_aes_key, nonce, ciphertext, tag = enc.hybrid_encrypt(msg.encode())

        sig = Signature(private_key_obj=self.sender.sig_key_obj)
        signature = sig.sign(msg.encode())

        cipher_b64 = b64(ciphertext)

        pkt = {
            "sender": "Sender",
            "enc_aes_key": b64(enc_aes_key),
            "nonce": b64(nonce),
            "ciphertext": cipher_b64,
            "tag": b64(tag),
            "signature": b64(signature)
        }
        save_json(PACKET_A_TO_B, pkt)

        # Packet display
        self.p_enc_key.delete("1.0", tk.END); self.p_enc_key.insert(tk.END, pkt["enc_aes_key"])
        self.p_nonce.delete(0, tk.END); self.p_nonce.insert(0, pkt["nonce"])
        self.p_cipher.delete("1.0", tk.END); self.p_cipher.insert(tk.END, pkt["ciphertext"])
        self.p_tag.delete(0, tk.END); self.p_tag.insert(0, pkt["tag"])
        self.p_sig.delete("1.0", tk.END); self.p_sig.insert(tk.END, pkt["signature"])

        # Chat log index
        insert_idx = self.sender_chat_log.index("end-1c")

        self.chat_history.append({
            "role": "Sender",
            "cipher": cipher_b64,
            "plain": msg,
            "line": insert_idx,
            "decrypted": False
        })
 
        self.add_to_chat(f"Sender: {cipher_b64}")
        self.sender_input.delete("1.0", tk.END)

    # Sending RECIPIENT to SENDER (encrypted send)
    def recipient_send(self):
        msg = self.recipient_input.get("1.0", tk.END).strip()
        if not msg:
            return messagebox.showwarning("Empty", "Recipient typed nothing.")

        if not (self.sender.has_keys() and self.recipient.has_keys()):
            return messagebox.showerror("Missing Keys", "Keys not generated or loaded.")

        enc = Encryption(self.sender.enc_pub_obj)
        enc_aes_key, nonce, ciphertext, tag = enc.hybrid_encrypt(msg.encode())

        sig = Signature(private_key_obj=self.recipient.sig_key_obj)
        signature = sig.sign(msg.encode())

        cipher_b64 = b64(ciphertext)

        pkt = {
            "sender": "Recipient",
            "enc_aes_key": b64(enc_aes_key),
            "nonce": b64(nonce),
            "ciphertext": cipher_b64,
            "tag": b64(tag),
            "signature": b64(signature)
        }
        save_json(PACKET_B_TO_A, pkt)

        # Packet display
        self.p_enc_key.delete("1.0", tk.END); self.p_enc_key.insert(tk.END, pkt["enc_aes_key"])
        self.p_nonce.delete(0, tk.END); self.p_nonce.insert(0, pkt["nonce"])
        self.p_cipher.delete("1.0", tk.END); self.p_cipher.insert(tk.END, pkt["ciphertext"])
        self.p_tag.delete(0, tk.END); self.p_tag.insert(0, pkt["tag"])
        self.p_sig.delete("1.0", tk.END); self.p_sig.insert(tk.END, pkt["signature"])

        insert_idx = self.sender_chat_log.index("end-1c")

        self.chat_history.append({
            "role": "Recipient",
            "cipher": cipher_b64,
            "plain": msg,
            "line": insert_idx,
            "decrypted": False
        })

        self.add_to_chat(f"Recipient: {cipher_b64}")
        self.recipient_input.delete("1.0", tk.END)

    # DECRYPT FOR RECIPIENT (decrypts Sender's message)
    
    def receive_for_recipient(self):
        if not os.path.exists(PACKET_A_TO_B):
            return self.output.insert(tk.END, "No messages to decrypt.\n")

        pkt = load_json(PACKET_A_TO_B)


        dec = Decryption(self.recipient.enc_key_obj)

        # retriving plaintext bytes
        plaintext_bytes = dec.hybrid_decrypt(
            ub64(pkt["enc_aes_key"]), ub64(pkt["nonce"]),
            ub64(pkt["ciphertext"]), ub64(pkt["tag"])
        )
        plaintext = plaintext_bytes.decode()

        sig = Signature(public_key_obj=self.sender.sig_pub_obj)
        valid = sig.verify(plaintext_bytes, ub64(pkt["signature"]))

        self.output.insert(
            tk.END,
            f"Recipient decrypted: {plaintext} ({'VALID' if valid else 'INVALID'})\n"
        )

        #A Feature to Replace ciphertext → plaintext
        for msg in reversed(self.chat_history):
            if msg["role"] == "Sender" and not msg["decrypted"]:
                msg["decrypted"] = True
                idx = msg["line"]
                new_line = f"Sender: {plaintext}"

                # Sender log
                self.sender_chat_log.config(state="normal")
                self.sender_chat_log.delete(idx, idx + " lineend")
                self.sender_chat_log.insert(idx, new_line)
                self.sender_chat_log.config(state="disabled")

                # Recipient log
                self.recipient_chat_log.config(state="normal")
                self.recipient_chat_log.delete(idx, idx + " lineend")
                self.recipient_chat_log.insert(idx, new_line)
                self.recipient_chat_log.config(state="disabled")
                break

    # DECRYPT FOR SENDER (decrypts Recipient's message)
    def receive_for_sender(self):
        if not os.path.exists(PACKET_B_TO_A):
            return self.output.insert(tk.END, "No messages to decrypt.\n")

        pkt = load_json(PACKET_B_TO_A)

        dec = Decryption(self.sender.enc_key_obj)
        plaintext_bytes = dec.hybrid_decrypt(
            ub64(pkt["enc_aes_key"]), ub64(pkt["nonce"]),
            ub64(pkt["ciphertext"]), ub64(pkt["tag"])
        )
        plaintext = plaintext_bytes.decode()

        sig = Signature(public_key_obj=self.recipient.sig_pub_obj)
        valid = sig.verify(plaintext_bytes, ub64(pkt["signature"]))

        self.output.insert(
            tk.END,
            f"Sender decrypted: {plaintext} ({'VALID' if valid else 'INVALID'})\n"
        )

        for msg in reversed(self.chat_history):
            if msg["role"] == "Recipient" and not msg["decrypted"]:
                msg["decrypted"] = True
                idx = msg["line"]
                new_line = f"Recipient: {plaintext}"

                self.sender_chat_log.config(state="normal")
                self.sender_chat_log.delete(idx, idx + " lineend")
                self.sender_chat_log.insert(idx, new_line)
                self.sender_chat_log.config(state="disabled")

                self.recipient_chat_log.config(state="normal")
                self.recipient_chat_log.delete(idx, idx + " lineend")
                self.recipient_chat_log.insert(idx, new_line)
                self.recipient_chat_log.config(state="disabled")
                break

    # CHAT LOG UPDATE
    def add_to_chat(self, line):
        self.sender_chat_log.config(state="normal")
        self.sender_chat_log.insert(tk.END, line + "\n")
        self.sender_chat_log.config(state="disabled")

        self.recipient_chat_log.config(state="normal")
        self.recipient_chat_log.insert(tk.END, line + "\n")
        self.recipient_chat_log.config(state="disabled")


def delete_keys():
    pem_file = glob.glob("*.pem")
    pem_file += glob.glob("*.json")
    for file_path in pem_file:
        try:
            os.remove(file_path)
        except Exception as e:
            print('error '+ {e})            
atexit.register(delete_keys)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()