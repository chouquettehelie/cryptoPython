# main_api.py
import os
import base64
from fastapi import FastAPI, UploadFile, File, Form
from aesgestion import AesGestion
from hashgestion import HashGestion
from rsagestion import RsaGestion
import uvicorn
import shutil

# Répertoire Windows centralisé pour toutes les clés
KEY_DIR = r"C:\Users\CIEL24_admin\Documents\CICD\mp00-applicationSecurite\cryptoPython"
os.makedirs(KEY_DIR, exist_ok=True)

app = FastAPI()

aes = AesGestion()
hash_gestion = HashGestion()
rsa = RsaGestion()

# ---------- AES ----------
@app.post("/aes/generate_key")
def generate_aes_key():
    # génère en mémoire via aesgestion
    aes.generate_aes_key()
    # sauvegarde dans fichier
    filename = os.path.join(KEY_DIR, "aes_key.bin")
    aes.save_aes_key_to_file(filename)
    # lis le contenu pour renvoyer en base64
    with open(filename, "rb") as f:
        key_bytes = f.read()
    key_b64 = base64.b64encode(key_bytes).decode("ascii")
    return {"status": "AES key generated and saved.", "key_base64": key_b64, "filepath": filename}

@app.post("/aes/load_key")
async def load_aes_key(file: UploadFile = File(...)):
    dest = os.path.join(KEY_DIR, file.filename)
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    # charge dans gestion
    aes.load_aes_key_from_file(dest)
    return {"status": f"AES key uploaded and saved to {dest}", "filepath": dest}

@app.post("/aes/encrypt_string")
def encrypt_string(data: str = Form(...)):
    result = aes.encrypt_string_to_base64(data)
    return {"encrypted": result}

@app.post("/aes/decrypt_string")
def decrypt_string(data: str = Form(...)):
    result = aes.decrypt_string_from_base64(data)
    return {"decrypted": result}

# ---------- HASH ----------
@app.post("/hash/sha256")
def sha256_string(data: str = Form(...)):
    result = hash_gestion.calculate_sha256(data)
    return {"sha256": result}

# ---------- RSA ----------
@app.post("/rsa/generate_keys")
def generate_rsa_keys(public_file: str = Form(...), private_file: str = Form(...), size: int = Form(...)):
    # Ensure filenames are just basenames and write into KEY_DIR
    pub_name = os.path.basename(public_file)
    priv_name = os.path.basename(private_file)
    pub_path = os.path.join(KEY_DIR, pub_name)
    priv_path = os.path.join(KEY_DIR, priv_name)

    # generate and save
    rsa.generation_clef(pub_path, priv_path, size)

    # read contents (PEM text)
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

@app.post("/rsa/encrypt")
def rsa_encrypt(data: str = Form(...)):
    encrypted = rsa.chiffrement_rsa(data)
    return {"encrypted": encrypted}

@app.post("/rsa/decrypt")
def rsa_decrypt(data: str = Form(...)):
    decrypted = rsa.dechiffrement_rsa(data)
    return {"decrypted": decrypted}

if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
