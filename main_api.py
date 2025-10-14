## @file main_api.py
#  @brief API FastAPI pour gérer AES, Hash et RSA dans cryptoPython.
#  @details Fournit des routes pour générer, sauvegarder, charger et utiliser les clés AES,
#           calculer des hashes SHA256, et gérer le chiffrement/déchiffrement RSA.
#  @author Helie Chouquette
#  @date 2025-10-14

from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
from aesgestion import AesGestion
from hashgestion import HashGestion
from rsagestion import RsaGestion
import uvicorn

app = FastAPI()

aes = AesGestion()
hash_gestion = HashGestion()
rsa = RsaGestion()

# ================= AES ====================

@app.post("/aes/generate_key")
def generate_aes_key():
    """!
    @brief Génère une clé AES.
    @return Status de la génération.
    """
    aes.generate_aes_key()
    return {"status": "AES key generated."}

@app.post("/aes/save_key")
def save_key(filename: str = Form(...)):
    """!
    @brief Sauvegarde la clé AES dans un fichier.
    @param filename Nom du fichier où la clé sera sauvegardée.
    @return Status de l'opération.
    """
    aes.save_aes_key_to_file(filename)
    return {"status": f"AES key saved to {filename}"}

@app.post("/aes/load_key")
def load_key(filename: str = Form(...)):
    """!
    @brief Charge une clé AES depuis un fichier.
    @param filename Nom du fichier contenant la clé.
    @return Status de l'opération.
    """
    aes.load_aes_key_from_file(filename)
    return {"status": f"AES key loaded from {filename}"}

@app.post("/aes/encrypt_string")
def encrypt_string(data: str = Form(...)):
    """!
    @brief Chiffre une chaîne de caractères avec AES.
    @param data Texte à chiffrer.
    @return Chaîne chiffrée en Base64.
    """
    result = aes.encrypt_string_to_base64(data)
    return {"encrypted": result}

@app.post("/aes/decrypt_string")
def decrypt_string(data: str = Form(...)):
    """!
    @brief Déchiffre une chaîne de caractères AES.
    @param data Texte chiffré en Base64.
    @return Texte déchiffré.
    """
    result = aes.decrypt_string_from_base64(data)
    return {"decrypted": result}

# ================= HASH ====================

@app.post("/hash/sha256")
def sha256_string(data: str = Form(...)):
    """!
    @brief Calcule le hash SHA256 d'une chaîne.
    @param data Texte à hasher.
    @return SHA256 du texte.
    """
    result = hash_gestion.calculate_sha256(data)
    return {"sha256": result}

# ================= RSA ====================

@app.post("/rsa/generate_keys")
def generate_rsa_keys(public_file: str = Form(...), private_file: str = Form(...), size: int = Form(...)):
    """!
    @brief Génère une paire de clés RSA.
    @param public_file Fichier pour la clé publique.
    @param private_file Fichier pour la clé privée.
    @param size Taille de la clé RSA.
    @return Status de l'opération.
    """
    rsa.generation_clef(public_file, private_file, size)
    return {"status": "RSA keys generated."}

@app.post("/rsa/load_keys")
def load_rsa_keys(pub_file: str = Form(...), priv_file: str = Form(...)):
    """!
    @brief Charge une paire de clés RSA depuis des fichiers.
    @param pub_file Fichier contenant la clé publique.
    @param priv_file Fichier contenant la clé privée.
    @return Status de l'opération.
    """
    rsa.chargement_clefs(pub_file, priv_file)
    return {"status": "RSA keys loaded."}

@app.post("/rsa/encrypt")
def rsa_encrypt(data: str = Form(...)):
    """!
    @brief Chiffre une chaîne avec RSA.
    @param data Texte à chiffrer.
    @return Chaîne chiffrée.
    """
    encrypted = rsa.chiffrement_rsa(data)
    return {"encrypted": encrypted}

@app.post("/rsa/decrypt")
def rsa_decrypt(data: str = Form(...)):
    """!
    @brief Déchiffre une chaîne RSA.
    @param data Texte chiffré.
    @return Texte déchiffré.
    """
    decrypted = rsa.dechiffrement_rsa(data)
    return {"decrypted": decrypted}

if __name__ == "__main__":
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)

