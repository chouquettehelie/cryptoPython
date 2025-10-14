## @file hashgestion.py
#  @brief Module de gestion des fonctions de hash SHA256.
#  @details Fournit des méthodes pour calculer le hash SHA256 d'une chaîne ou d'un fichier.
#  @author Helie Chouquette
#  @date 2025-10-14

import hashlib

class HashGestion:
    """!
    @brief Classe pour la gestion du hash SHA256.
    @details Permet de calculer le SHA256 de chaînes de caractères ou de fichiers.
    """

    def __init__(self):
        """!
        @brief Constructeur de la classe HashGestion.
        @details Affiche un message de création de l'objet.
        """
        print("Constructeur par défaut du Hash")

    def __del__(self):
        """!
        @brief Destructeur de la classe HashGestion.
        @details Affiche un message de destruction de l'objet.
        """
        print("Destructeur par défaut du Hash")

    def calculate_sha256(self, input_string: str) -> str:
        """!
        @brief Calcule le hash SHA256 d'une chaîne.
        @param input_string Chaîne de caractères à hasher.
        @return Hash SHA256 sous forme hexadécimale en majuscules.
        """
        sha256 = hashlib.sha256()
        sha256.update(input_string.encode('utf-8'))
        return sha256.hexdigest().upper()

    def calculate_file_sha256(self, filename: str) -> str:
        """!
        @brief Calcule le hash SHA256 d'un fichier.
        @param filename Chemin du fichier à hasher.
        @return Hash SHA256 du fichier sous forme hexadécimale en majuscules.
        @details Retourne une chaîne vide si le fichier est introuvable.
        """
        sha256 = hashlib.sha256()
        try:
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest().upper()
        except FileNotFoundError:
            print("Impossible d'ouvrir le fichier.")
            return ""

