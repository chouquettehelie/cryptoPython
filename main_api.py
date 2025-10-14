# main_api.py
import os
import base64
from fastapi import FastAPI, UploadFile, File, Form
from aesgestion import AesGestion
from hashgestion import HashGestion
from rsagestion import RsaGestion
import uvicorn
import shutil

##
# @file main_api.py
# @brief API principale FastAPI pour le chiffrement AES, RSA et le hachage SHA-256.
# 
# Ce module fournit plusieurs endpoints REST permettant :
# - de générer et charger des clés AES et RSA,
# - de chiffrer et déchiffrer des chaînes de texte,
# - de calculer des empreintes SHA-256.
#

# Répertoire Windows centralisé pour toutes les clés
KEY_DIR = r"C:\Users\CIEL24_admin\Documents\CICD\mp00-applicationSecurite\cryptoPython"
os.makedirs(KEY_DIR, exist_ok=True)

app = FastAPI()

aes = AesGestion()
hash_gestion = HashGestion()
rsa = RsaGestion()

# ---------- AES ----------

##
# @brief Génère une clé AES et la sauvegarde dans un fichier.
# 
# Cette fonction :
# - génère une clé AES via la classe @ref AesGestion,
# - la sauvegarde dans un fichier local (`aes_key.bin`),
# - renvoie la clé encodée en base64 et le chemin du fichier.
# 
# @return dict contenant :
# - "status" : message de succès,
# - "key_base64" : clé AES encodée en base64,
# - "filepath" : chemin complet du fichier de clé.
#
@app.post("/aes/generate_key")
def generate_aes_key():
    aes.generate_aes_key()
    filename = os.path.join(KEY_DIR, "aes_key.bin")
    aes.save_aes_key_to_file(filename)
    with open(filename, "rb") as f:
        key_bytes = f.read()
    key_b64 = base64.b64encode(key_bytes).decode("ascii")
    return {"status": "AES key generated and saved.", "key_base64": key_b64, "filepath": filename}

##
# @brief Charge une clé AES à partir d’un fichier uploadé.
# 
# Le fichier est copié dans le répertoire @ref KEY_DIR puis chargé en mémoire.
# 
# @param file Le fichier uploadé contenant la clé AES.
# @return dict contenant le statut et le chemin du fichier sauvegardé.
#
@app.post("/aes/load_key")
async def load_aes_key(file: UploadFile = File(...)):
    dest = os.path.join(KEY_DIR, file.filename)
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    aes.load_aes_key_from_file(dest)
    return {"status": f"AES key uploaded and saved to {dest}", "filepath": dest}

##
# @brief Chiffre une chaîne de caractères en AES.
# 
# @param data Chaîne de texte à chiffrer.
# @return dict contenant la chaîne chiffrée en base64 sous la clé "encrypted".
#
@app.post("/aes/encrypt_string")
def encrypt_string(data: str = Form(...)):
    result = aes.encrypt_string_to_base64(data)
    return {"encrypted": result}

##
# @brief Déchiffre une chaîne de caractères AES en clair.
# 
# @param data Chaîne chiffrée (base64).
# @return dict contenant la chaîne déchiffrée sous la clé "decrypted".
#
@app.post("/aes/decrypt_string")
def decrypt_string(data: str = Form(...)):
    result = aes.decrypt_string_from_base64(data)
    return {"decrypted": result}

# ---------- HASH ----------

##
# @brief Calcule le hachage SHA-256 d’une chaîne de caractères.
# 
# @param data Chaîne à hacher.
# @return dict contenant l’empreinte SHA-256 sous la clé "sha256".
#
@app.post("/hash/sha256")
def sha256_string(data: str = Form(...)):
    result = hash_gestion.calculate_sha256(data)
    return {"sha256": result}

# ---------- RSA ----------

##
# @brief Génère une paire de clés RSA et les sauvegarde sur disque.
# 
# @param public_file Nom du fichier de clé publique.
# @param private_file Nom du fichier de clé privée.
# @param size Taille de la clé RSA (ex: 2048, 4096).
# @return dict contenant les clés publiques et privées en PEM et leurs chemins.
#
@app.post("/rsa/generate_keys")
def generate_rsa_keys(public_file: str = Form(...), private_file: str = Form(...), size: int = Form(...)):
    pub_name = os.path.basename(public_file)
    priv_name = os.path.basename(private_file)
    pub_path = os.path.join(KEY_DIR, pub_name)
    priv_path = os.path.join(KEY_DIR, priv_name)

    rsa.generation_clef(pub_path, priv_path, size)

    with open(pub_path, "r", encoding="utf-8") as f:
        pub_pem = f.read()
    with open(priv_path, "r", encoding="utf-8") as f:
        priv_pem = f.read()

    return {
        "status": "RSA keys generated and saved.",
        "public_key_pem": pub_pem,
        "private_key_pem": priv_pem,
        "public_path": pub_path,
        "private_path": priv_path
    }

##
# @brief Charge une paire de clés RSA à partir de fichiers uploadés.
# 
# @param pub_file Fichier de clé publique.
# @param priv_file Fichier de clé privée.
# @return dict indiquant les chemins des fichiers enregistrés.
#
@app.post("/rsa/load_keys")
async def load_rsa_keys(pub_file: UploadFile = File(...), priv_file: UploadFile = File(...)):
    pub_dest = os.path.join(KEY_DIR, pub_file.filename)
    priv_dest = os.path.join(KEY_DIR, priv_file.filename)
    with open(pub_dest, "wb") as f:
        shutil.copyfileobj(pub_file.file, f)
    with open(priv_dest, "wb") as f:
        shutil.copyfileobj(priv_file.file, f)
    rsa.chargement_clefs(pub_dest, priv_dest)
    return {"status": "RSA keys uploaded and saved.", "public_path": pub_dest, "private_path": priv_dest}

##
# @brief Chiffre une chaîne en RSA via la clé publique chargée.
# 
# @param data Chaîne à chiffrer.
# @return dict contenant la donnée chiffrée sous la clé "encrypted".
#
@app.post("/rsa/encrypt")
def rsa_encrypt(data: str = Form(...)):
    encrypted = rsa.chiffrement_rsa(data)
    return {"encrypted": encrypted}

##
# @brief Déchiffre une chaîne RSA via la clé privée chargée.
# 
# @param data Donnée chiffrée (base64 ou texte RSA).
# @return dict contenant le texte déchiffré sous la clé "decrypted".
#
@app.post("/rsa/decrypt")
def rsa_decrypt(data: str = Form(...)):
    decrypted = rsa.dechiffrement_rsa(data_
