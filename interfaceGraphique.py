import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests

API_URL = "http://192.168.1.60:8000"  # ton serveur

def call_api(endpoint, data):
    try:
        res = requests.post(f"{API_URL}{endpoint}", data=data)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        messagebox.showerror("Erreur API", f"Impossible de joindre l'API :\n{e}")
        return {}

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Crypto GUI")
        root.resizable(False, False)

        self.cipher_type = tk.StringVar(value="AES")
        self.aes_loaded = False
        self.rsa_loaded = False

        # --- Choix méthode ---
        frame_top = tk.Frame(root, padx=10, pady=10)
        frame_top.grid(row=0, column=0, sticky="w")
        tk.Label(frame_top, text="Méthode :").grid(row=0, column=0, sticky='e')
        tk.OptionMenu(frame_top, self.cipher_type, "AES", "RSA").grid(row=0, column=1, sticky='w')

        # --- Clés ---
        frame_keys = tk.Frame(root, padx=10, pady=5)
        frame_keys.grid(row=1, column=0, sticky="w")
        tk.Button(frame_keys, text="Générer clé AES", width=15, command=self.generate_aes_key).grid(row=0, column=0, padx=5, pady=3)
        tk.Button(frame_keys, text="Charger clés RSA", width=15, command=self.load_rsa_keys).grid(row=0, column=1, padx=5, pady=3)
        tk.Button(frame_keys, text="Générer clés RSA", width=15, command=self.generate_rsa_keys).grid(row=0, column=2, padx=5, pady=3)

        # --- Actions ---
        frame_actions = tk.Frame(root, padx=10, pady=10)
        frame_actions.grid(row=2, column=0, sticky="w")
        tk.Button(frame_actions, text="Chiffrer", width=12, command=self.encrypt_data).grid(row=0, column=0, padx=5, pady=3)
        tk.Button(frame_actions, text="Déchiffrer", width=12, command=self.decrypt_data).grid(row=0, column=1, padx=5, pady=3)
        tk.Button(frame_actions, text="SHA-256", width=12, command=self.hash_sha256).grid(row=0, column=2, padx=5, pady=3)

        # --- Résultat ---
        frame_result = tk.Frame(root, padx=10, pady=5)
        frame_result.grid(row=3, column=0, sticky="w")
        tk.Label(frame_result, text="Résultat :").grid(row=0, column=0, sticky='w')
        self.result_text = tk.Text(frame_result, height=6, width=60, wrap='word')
        self.result_text.grid(row=1, column=0, pady=5)

        # --- Bas ---
        frame_bottom = tk.Frame(root, padx=10, pady=10)
        frame_bottom.grid(row=4, column=0, sticky="e")
        tk.Button(frame_bottom, text="Effacer", width=10, command=self.clear_result).grid(row=0, column=0, padx=5)
        tk.Button(frame_bottom, text="Quitter", width=10, command=root.destroy).grid(row=0, column=1, padx=5)

    def set_result(self, text):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)

    def clear_result(self):
        self.result_text.delete("1.0", tk.END)

    # --- Clés AES ---
    def generate_aes_key(self):
        res = call_api("/aes/generate_key", {})
        status = res.get("status")
        if status:
            messagebox.showinfo("AES", status)
            self.aes_loaded = True

    # --- Clés RSA ---
    def generate_rsa_keys(self):
        pub_file = simpledialog.askstring("RSA", "Nom fichier clé publique (sera créé) :")
        if not pub_file: return
        priv_file = simpledialog.askstring("RSA", "Nom fichier clé privée (sera créé) :")
        if not priv_file: return
        size = simpledialog.askinteger("RSA", "Taille clé RSA (ex: 2048) :", initialvalue=2048)
        if not size: return
        res = call_api("/rsa/generate_keys", {"public_file": pub_file, "private_file": priv_file, "size": size})
        status = res.get("status")
        if status:
            messagebox.showinfo("RSA", status)
            self.rsa_loaded = True

    def load_rsa_keys(self):
        pub = filedialog.askopenfilename(title="Clé publique RSA")
        if not pub: return
        priv = filedialog.askopenfilename(title="Clé privée RSA")
        if not priv: return
        res = call_api("/rsa/load_keys", {"pub_file": pub, "priv_file": priv})
        status = res.get("status")
        if status:
            messagebox.showinfo("RSA", status)
            self.rsa_loaded = True

    # --- Actions ---
    def encrypt_data(self):
        data = simpledialog.askstring("Chiffrement", "Texte à chiffrer :")
        if not data: return
        if self.cipher_type.get() == "AES":
            if not self.aes_loaded:
                messagebox.showwarning("AES", "Veuillez générer la clé AES avant de chiffrer.")
                return
            res = call_api("/aes/encrypt_string", {"data": data})
            encrypted = res.get("encrypted")
            if encrypted: self.set_result(encrypted)
        else:
            if not self.rsa_loaded:
                messagebox.showwarning("RSA", "Veuillez générer ou charger les clés RSA avant de chiffrer.")
                return
            res = call_api("/rsa/encrypt", {"data": data})
            encrypted = res.get("encrypted")
            if encrypted: self.set_result(encrypted)

    def decrypt_data(self):
        data = simpledialog.askstring("Déchiffrement", "Texte chiffré :")
        if not data: return
        if self.cipher_type.get() == "AES":
            if not self.aes_loaded:
                messagebox.showwarning("AES", "Veuillez générer la clé AES avant de déchiffrer.")
                return
            res = call_api("/aes/decrypt_string", {"data": data})
            decrypted = res.get("decrypted")
            if decrypted: self.set_result(decrypted)
        else:
            if not self.rsa_loaded:
                messagebox.showwarning("RSA", "Veuillez générer ou charger les clés RSA avant de déchiffrer.")
                return
            res = call_api("/rsa/decrypt", {"data": data})
            decrypted = res.get("decrypted")
            if decrypted: self.set_result(decrypted)

    def hash_sha256(self):
        data = simpledialog.askstring("SHA-256", "Texte à hacher :")
        if not data: return
        res = call_api("/hash/sha256", {"data": data})
        sha = res.get("sha256")
        if sha: self.set_result(sha)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
