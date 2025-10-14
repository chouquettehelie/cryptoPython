## @file aesgestion.py
#  @brief Module de gestion du chiffrement AES pour le projet cryptoPython.
#  @details Ce module fournit des méthodes pour générer, sauvegarder et charger une clé AES,
#  ainsi que pour chiffrer et déchiffrer des fichiers ou des chaînes de caractères en mode CBC.
#
#  @author
#  Helie Chouquette
#  @date
#  2025-10-14
#  @version 1.0

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AesGestion:
    """!
    @brief Classe pour la gestion du chiffrement AES-256.
    @details Permet de générer une clé AES, de sauvegarder/charger celle-ci
    et de chiffrer/déchiffrer des fichiers ou des chaînes de texte.
    """

    def __init__(self):
        """!
        @brief Constructeur de la classe AesGestion.
        @details Initialise la clé AES et le vecteur d’initialisation à None.
        """
        self.aes_key = None
        self.iv = None

    def generate_aes_key(self):
        """!
        @brief Génère une nouvelle clé AES-256.
        @details La clé générée est de 32 octets (256 bits) et stockée dans l’attribut `aes_key`.
        """
        self.aes_key = get_random_bytes(32)  # 256-bit key

    def save_aes_key_to_file(self, filename):
        """!
        @brief Sauvegarde la clé AES dans un fichier.
        @param filename Nom du fichier où la clé sera sauvegardée.
        @exception ValueError Si la clé AES n’a pas été générée.
        """
        if not self.aes_key:
            raise ValueError("AES key not generated.")
        with open(filename, "wb") as f:
            f.write(self.aes_key)

    def load_aes_key_from_file(self, filename):
        """!
        @brief Charge une clé AES depuis un fichier.
        @param filename Nom du fichier contenant la clé.
        @exception ValueError Si la taille de la clé est invalide.
        """
        with open(filename, "rb") as f:
            self.aes_key = f.read()
        if len(self.aes_key) != 32:
            raise ValueError("Invalid AES-256 key size")

    def encrypt_file(self, input_file, output_file):
        """!
        @brief Chiffre un fichier avec AES-CBC.
        @param input_file Chemin du fichier à chiffrer.
        @param output_file Chemin du fichier chiffré à générer.
        """
        self.iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

        with open(input_file, "rb") as f:
            plaintext = f.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open(output_file, "wb") as f:
            f.write(self.iv + ciphertext)

    def decrypt_file(self, input_file, output_file):
        """!
        @brief Déchiffre un fichier chiffré avec AES-CBC.
        @param input_file Chemin du fichier chiffré.
        @param output_file Chemin du fichier déchiffré à générer.
        """
        with open(input_file, "rb") as f:
            file_content = f.read()

        self.iv = file_content[:16]
        ciphertext = file_content[16:]

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        with open(output_file, "wb") as f:
            f.write(plaintext)

    def encrypt_string_to_base64(self, plaintext: str) -> str:
        """!
        @brief Chiffre une chaîne de caractères en Base64.
        @param plaintext Chaîne à chiffrer.
        @return Chaîne chiffrée en Base64.
        """
        self.iv = get_random_bytes(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded)

        combined = self.iv + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_string_from_base64(self, base64_data: str) -> str:
        """!
        @brief Déchiffre une chaîne chiffrée en Base64.
        @param base64_data Données chiffrées en Base64.
        @return Chaîne déchiffrée.
        """
        combined = base64.b64decode(base64_data)
        self.iv = combined[:16]
        ciphertext = combined[16:]

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')

