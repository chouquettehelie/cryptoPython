import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import requests

# Répertoire local Windows pour stocker les clés
LOCAL_DIR = r"C:\Users\CIEL24_admin\Documents\CICD\mp00-applicationSecurite\cryptoPython"

<<<<<<< HEAD
## 
# @brief Appelle une API REST distante via une requête POST.
# @param endpoint L'endpoint de l'API (ex: "/aes/encrypt_string").
# @param data Le dictionnaire contenant les données à envoyer dans la requête POST.
# @return Le résultat JSON de la réponse de l'API ou {} en cas d'erreur.
#
def call_api(endpoint, data):
=======
# Assurer que le dossier existe
os.makedirs(LOCAL_DIR, exist_ok=True)

API_URL = "http://192.168.1.60:8000"  # Adresse de ton serveur

def call_api(endpoint, data=None):
    """Appel POST vers l'API FastAPI."""
>>>>>>> c8e132b971aac1473bbb112289467aaf880b3db3
    try:
        res = requests.post(f"{API_URL}{endpoint}", data=data or {})
        res.raise_for_status()
        return res.json()
    except Exception as e:
        messagebox.showerror("Erreur API", f"Impossible de joindre l'API :\n{e}")
        return {}

##
# @class CryptoGUI
# @brief Classe principale gérant l'interface graphique de chiffrement/déchiffrement.
#
class CryptoGUI:
    ##
    # @brief Constructeur de la fenêtre principale et création des onglets.
    # @param root La fenêtre principale Tkinter.
    #
    def __init__(self, root):
        self.root = root
        root.title("Crypto GUI")
        root.geometry("650x450")
        root.resizable(False, False)

        self.aes_loaded = False
        self.rsa_loaded = False

        # Onglets
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.tab_aes = ttk.Frame(self.notebook)
        self.tab_rsa = ttk.Frame(self.notebook)
        self.tab_hash = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_aes, text="AES")
        self.notebook.add(self.tab_rsa, text="RSA")
        self.notebook.add(self.tab_hash, text="SHA-256")

        self.create_aes_tab()
        self.create_rsa_tab()
        self.create_hash_tab()

    # ---------------- AES ----------------
    ##
    # @brief Crée les éléments graphiques pour l’onglet AES.
    #
    def create_aes_tab(self):
        frame_buttons = tk.Frame(self.tab_aes)
        frame_buttons.pack(pady=15) 
        tk.Button(frame_buttons, text="Générer clé AES", bg="#4CAF50", fg="white", font=("Arial", 11),
                  width=20, command=self.generate_aes_key).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame_buttons, text="Charger clé AES", bg="#2196F3", fg="white", font=("Arial", 11),
                  width=20, command=self.load_aes_key).grid(row=0, column=1, padx=5, pady=5)

        frame_actions = tk.Frame(self.tab_aes)
        frame_actions.pack(pady=10)
        tk.Button(frame_actions, text="Chiffrer", bg="#FF9800", fg="white", font=("Arial", 11),
                  width=15, command=self.encrypt_aes).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame_actions, text="Déchiffrer", bg="#f44336", fg="white", font=("Arial", 11),
                  width=15, command=self.decrypt_aes).grid(row=0, column=1, padx=5, pady=5)

        self.result_aes = tk.Text(self.tab_aes, height=8, width=70, bg="#f0f0f0", font=("Courier", 11))
        self.result_aes.pack(pady=10)

    # ---------------- RSA ----------------
    ##
    # @brief Crée les éléments graphiques pour l’onglet RSA.
    #
    def create_rsa_tab(self):
        frame_buttons = tk.Frame(self.tab_rsa)
        frame_buttons.pack(pady=15) 
        tk.Button(frame_buttons, text="Générer clés RSA", bg="#4CAF50", fg="white", font=("Arial", 11),
                  width=20, command=self.generate_rsa_keys).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame_buttons, text="Charger clés RSA", bg="#2196F3", fg="white", font=("Arial", 11),
                  width=20, command=self.load_rsa_keys).grid(row=0, column=1, padx=5, pady=5)

        frame_actions = tk.Frame(self.tab_rsa)
        frame_actions.pack(pady=10)
        tk.Button(frame_actions, text="Chiffrer", bg="#FF9800", fg="white", font=("Arial", 11),
                  width=15, command=self.encrypt_rsa).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame_actions, text="Déchiffrer", bg="#f44336", fg="white", font=("Arial", 11),
                  width=15, command=self.decrypt_rsa).grid(row=0, column=1, padx=5, pady=5)

        self.result_rsa = tk.Text(self.tab_rsa, height=8, width=70, bg="#f0f0f0", font=("Courier", 11))
        self.result_rsa.pack(pady=10)

    # ---------------- SHA-256 ----------------
    ##
    # @brief Crée les éléments graphiques pour l’onglet de hachage SHA-256.
    #
    def create_hash_tab(self):
        frame_actions = tk.Frame(self.tab_hash)
        frame_actions.pack(pady=15)

        tk.Button(frame_actions, text="Calculer SHA-256", bg="#9C27B0", fg="white", font=("Arial", 11),
                  width=25, command=self.hash_sha256).pack(pady=5) 
        self.result_hash = tk.Text(self.tab_hash, height=8, width=70, bg="#f0f0f0", font=("Courier", 11))
        self.result_hash.pack(pady=10)

    # ---------------- AES Actions ----------------
    ##
    # @brief Génère une clé AES via l’API.
    #
    def generate_aes_key(self):
        res = call_api("/aes/generate_key")
        if not res: return
        key_b64 = res.get("key_base64")
        if key_b64:
            key_bytes = base64.b64decode(key_b64)
            local_path = os.path.join(LOCAL_DIR, "aes_key.bin")
            with open(local_path, "wb") as f:
                f.write(key_bytes)
            messagebox.showinfo("AES", f"Clé AES générée et sauvegardée localement :\n{local_path}")
            self.aes_loaded = True

    ##
    # @brief Charge une clé AES depuis un fichier local.
    #
    def load_aes_key(self):
        filepath = filedialog.askopenfilename(title="Choisir la clé AES")
        if filepath:
            # Copier la clé dans LOCAL_DIR
            filename = os.path.join(LOCAL_DIR, os.path.basename(filepath))
            with open(filepath, "rb") as f_in, open(filename, "wb") as f_out:
                f_out.write(f_in.read())
            messagebox.showinfo("AES", f"Clé AES copiée localement :\n{filename}")
            self.aes_loaded = True

    ##
    # @brief Chiffre une chaîne avec AES via l’API.
    #
    def encrypt_aes(self):
        if not self.aes_loaded:
            messagebox.showwarning("AES", "Générez ou chargez la clé AES avant de chiffrer.")
            return
        data = simpledialog.askstring("AES Chiffrement", "Texte à chiffrer :")
        if data:
            res = call_api("/aes/encrypt_string", {"data": data}) 
            encrypted = res.get("encrypted")
            if encrypted:
                self.result_aes.delete("1.0", tk.END)
                self.result_aes.insert(tk.END, encrypted)

    ##
    # @brief Déchiffre une chaîne AES via l’API.
    #
    def decrypt_aes(self):
        if not self.aes_loaded:
            messagebox.showwarning("AES", "Générez ou chargez la clé AES avant de déchiffrer.")
            return
        data = simpledialog.askstring("AES Déchiffrement", "Texte chiffré :")
        if data:
            res = call_api("/aes/decrypt_string", {"data": data})
            decrypted = res.get("decrypted")
            if decrypted:
                self.result_aes.delete("1.0", tk.END)
                self.result_aes.insert(tk.END, decrypted)

    # ---------------- RSA Actions ----------------
    ##
    # @brief Génère une paire de clés RSA via l’API.
    #
    def generate_rsa_keys(self):
        pub_name = simpledialog.askstring("RSA", "Nom fichier clé publique :", initialvalue="rsa_pub.pem")
        if not pub_name: return
        priv_name = simpledialog.askstring("RSA", "Nom fichier clé privée :", initialvalue="rsa_priv.pem")
        if not priv_name: return
        size = simpledialog.askinteger("RSA", "Taille clé RSA :", initialvalue=2048)
        if not size: return

        res = call_api("/rsa/generate_keys", {"public_file": pub_name, "private_file": priv_name, "size": size})
        if not res: return

        # Récupération des PEM depuis le serveur
        pub_pem = res.get("public_key_pem")
        priv_pem = res.get("private_key_pem")

        if pub_pem and priv_pem:
            local_pub = os.path.join(LOCAL_DIR, pub_name)
            local_priv = os.path.join(LOCAL_DIR, priv_name)
            with open(local_pub, "w", encoding="utf-8") as f: f.write(pub_pem)
            with open(local_priv, "w", encoding="utf-8") as f: f.write(priv_pem)
            messagebox.showinfo("RSA", f"Clés RSA générées et sauvegardées localement:\n{local_pub}\n{local_priv}")
            self.rsa_loaded = True

    ##
    # @brief Charge des clés RSA existantes depuis des fichiers.
    #
    def load_rsa_keys(self):
        pub = filedialog.askopenfilename(title="Clé publique RSA")
        if not pub: return
        priv = filedialog.askopenfilename(title="Clé privée RSA")
        if not priv: return
        # Copier les fichiers dans LOCAL_DIR
        local_pub = os.path.join(LOCAL_DIR, os.path.basename(pub))
        local_priv = os.path.join(LOCAL_DIR, os.path.basename(priv))
        for src, dst in [(pub, local_pub), (priv, local_priv)]:
            with open(src, "rb") as f_in, open(dst, "wb") as f_out:
                f_out.write(f_in.read())
        messagebox.showinfo("RSA", f"Clés RSA copiées localement:\n{local_pub}\n{local_priv}")
        self.rsa_loaded = True

    ##
    # @brief Chiffre une chaîne de texte avec la clé publique RSA.
    #
    def encrypt_rsa(self):
        if not self.rsa_loaded:
            messagebox.showwarning("RSA", "Générez ou chargez les clés RSA avant de chiffrer.")
            return
        data = simpledialog.askstring("RSA Chiffrement", "Texte à chiffrer :")
        if data:
            res = call_api("/rsa/encrypt", {"data": data})
            encrypted = res.get("encrypted")
            if encrypted:  
                self.result_rsa.delete("1.0", tk.END)
                self.result_rsa.insert(tk.END, encrypted)

    ##
    # @brief Déchiffre un texte RSA avec la clé privée.
    #
    def decrypt_rsa(self):
        if not self.rsa_loaded:
            messagebox.showwarning("RSA", "Générez ou chargez les clés RSA avant de déchiffrer.")
            return
        data = simpledialog.askstring("RSA Déchiffrement", "Texte chiffré :")
        if data:
            res = call_api("/rsa/decrypt", {"data": data})
            decrypted = res.get("decrypted")
            if decrypted:
                self.result_rsa.delete("1.0", tk.END)
                self.result_rsa.insert(tk.END, decrypted)

<<<<<<< HEAD
    # ---------------- SHA-256 Action ----------------
    ##
    # @brief Calcule le hachage SHA-256 d’une chaîne via l’API.
    #
=======
    # ---------------- SHA-256 ----------------
>>>>>>> c8e132b971aac1473bbb112289467aaf880b3db3
    def hash_sha256(self):
        data = simpledialog.askstring("SHA-256", "Texte à hacher :")
        if data:
            res = call_api("/hash/sha256", {"data": data})
            sha = res.get("sha256")
            if sha:
                self.result_hash.delete("1.0", tk.END)
                self.result_hash.insert(tk.END, sha)

# ---------------- Lancer GUI ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()

