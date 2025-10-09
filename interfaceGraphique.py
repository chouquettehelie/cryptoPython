import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests
from requests.exceptions import RequestException

API_URL = "http://192.168.1.140:8000"  #test

def call_api(endpoint, data):
    """Appel à l'API (envoie des champs en form-data). Retourne dict ou {} en cas d'erreur."""
    try:
        res = requests.post(f"{API_URL}{endpoint}", data=data)
        res.raise_for_status()
        return res.json()
    except RequestException as e:
        messagebox.showerror("Erreur API", f"Impossible de joindre l'API :\n{e}")
        return {}
    except ValueError:
        messagebox.showerror("Erreur", "Réponse API non JSON.")
        return {}

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Crypto GUI")
        root.resizable(False, False)

        self.cipher_type = tk.StringVar(value="AES")

        # Choix méthode
        frame_top = tk.Frame(root, padx=10, pady=10)
        frame_top.grid(row=0, column=0, sticky="w")
        tk.Label(frame_top, text="Méthode de chiffrement :").grid(row=0, column=0, sticky='e')
        tk.OptionMenu(frame_top, self.cipher_type, "AES", "RSA").grid(row=0, column=1, sticky='w')

        # Clé AES
        
        frame_aes = tk.Frame(root, padx=10, pady=5)
        frame_aes.grid(row=1, column=0, sticky="w")
        tk.Label(frame_aes, text="Clé AES :").grid(row=0, column=0, sticky='e')
        tk.Button(frame_aes, text="Charger", width=12, command=self.load_aes_key).grid(row=0, column=1, sticky='w')

        # Clés RSA
        frame_rsa = tk.Frame(root, padx=10, pady=5)
        frame_rsa.grid(row=2, column=0, sticky="w")
        tk.Label(frame_rsa, text="Clé RSA :").grid(row=0, column=0, sticky='e')
        tk.Button(frame_rsa, text="Charger (pub/priv)", width=16, command=self.load_rsa_keys).grid(row=0, column=1, sticky='w')

        # Actions (Chiffrer / Déchiffrer / SHA-256)
        frame_actions = tk.Frame(root, padx=10, pady=10)
        frame_actions.grid(row=3, column=0, sticky="w")

        tk.Button(frame_actions, text="Chiffrer", width=12, command=self.encrypt_data).grid(row=0, column=0, padx=5, pady=3)
        tk.Button(frame_actions, text="Déchiffrer", width=12, command=self.decrypt_data).grid(row=0, column=1, padx=5, pady=3)
        tk.Button(frame_actions, text="SHA-256", width=12, command=self.hash_sha256).grid(row=0, column=2, padx=5, pady=3)

        # Résultat (Text area)
        frame_result = tk.Frame(root, padx=10, pady=5)
        frame_result.grid(row=4, column=0, sticky="w")
        tk.Label(frame_result, text="Résultat :").grid(row=0, column=0, sticky='w')
        self.result_text = tk.Text(frame_result, height=6, width=60, wrap='word')
        self.result_text.grid(row=1, column=0, pady=5)

        # Bas (Clear / Quit)
        frame_bottom = tk.Frame(root, padx=10, pady=10)
        frame_bottom.grid(row=5, column=0, sticky="e")
        tk.Button(frame_bottom, text="Effacer", width=10, command=self.clear_result).grid(row=0, column=0, padx=5)
        tk.Button(frame_bottom, text="Quitter", width=10, command=root.destroy).grid(row=0, column=1, padx=5)

    def set_result(self, text):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)

    def clear_result(self):
        self.result_text.delete("1.0", tk.END)

    def load_aes_key(self):
        filepath = filedialog.askopenfilename(title="Choisir la clé AES")
        if filepath:
            res = call_api("/aes/load_key", {"filename": filepath})
            status = res.get("status", None)
            if status:
                messagebox.showinfo("Chargement AES", status)
            else:
                messagebox.showwarning("Chargement AES", "Réponse inattendue de l'API.")

    def load_rsa_keys(self):
        pub = filedialog.askopenfilename(title="Clé publique RSA (fichier PEM)")
        if not pub:
            return
        priv = filedialog.askopenfilename(title="Clé privée RSA (fichier PEM)")
        if not priv:
            return
        res = call_api("/rsa/load_keys", {"pub_file": pub, "priv_file": priv})
        status = res.get("status", None)
        if status:
            messagebox.showinfo("Chargement RSA", status)
        else:
            messagebox.showwarning("Chargement RSA", "Réponse inattendue de l'API.")

    def encrypt_data(self):
        data = simpledialog.askstring("Chiffrement", "Texte à chiffrer :")
        if data is None:
            return  # annulation
        if self.cipher_type.get() == "AES":
            res = call_api("/aes/encrypt_string", {"data": data})
            encrypted = res.get("encrypted", None)
            if encrypted is not None:
                self.set_result(encrypted)
            else:
                messagebox.showwarning("Erreur", "Réponse inattendue de l'API.")
        else:  # RSA
            res = call_api("/rsa/encrypt", {"data": data})
            encrypted = res.get("encrypted", None)
            if encrypted is not None:
                self.set_result(encrypted)
            else:
                messagebox.showwarning("Erreur", "Réponse inattendue de l'API.")

    def decrypt_data(self):
        data = simpledialog.askstring("Déchiffrement", "Texte chiffré (Base64 pour RSA/AES) :")
        if data is None:
            return
        if self.cipher_type.get() == "AES":
            res = call_api("/aes/decrypt_string", {"data": data})
            decrypted = res.get("decrypted", None)
            if decrypted is not None:
                self.set_result(decrypted)
            else:
                messagebox.showwarning("Erreur", "Réponse inattendue de l'API.")
        else:
            res = call_api("/rsa/decrypt", {"data": data})
            decrypted = res.get("decrypted", None)
            if decrypted is not None:
                self.set_result(decrypted)
            else:
                messagebox.showwarning("Erreur", "Réponse inattendue de l'API.")

    def hash_sha256(self):
        data = simpledialog.askstring("SHA-256", "Texte à hacher :")
        if data is None:
            return
        res = call_api("/hash/sha256", {"data": data})
        sha = res.get("sha256", None)
        if sha is not None:
            self.set_result(sha)
        else:
            messagebox.showwarning("Erreur", "Réponse inattendue de l'API.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
