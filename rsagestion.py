## @file rsagestion.py
#  @brief Module de gestion du chiffrement RSA.
#  @details Fournit des méthodes pour générer, charger, chiffrer et déchiffrer des données et fichiers avec RSA.
#  @author Helie Chouquette
#  @date 2025-10-14

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import os

class RsaGestion:
    """!
    @brief Classe pour la gestion des clés et chiffrement RSA.
    @details Permet de générer des clés RSA, charger des clés depuis des fichiers,
             chiffrer/déchiffrer des chaînes et fichiers.
    """

    def __init__(self):
        """!
        @brief Constructeur de la classe RsaGestion.
        @details Initialise les clés publiques et privées à None.
        """
        print("Construction de la classe")
        self.clefPrive = None
        self.clefPublic = None

    def __del__(self):
        """!
        @brief Destructeur de la classe RsaGestion.
        """
        print("Destructeur par défaut du RSA")

    def generation_clef(self, nom_fichier_public, nom_fichier_prive, taille):
        """!
        @brief Génère une paire de clés RSA.
        @param nom_fichier_public Nom du fichier pour la clé publique.
        @param nom_fichier_prive Nom du fichier pour la clé privée.
        @param taille Taille de la clé en bits.
        """
        key = RSA.generate(taille)
        self.clefPrive = key
        self.clefPublic = key.publickey()

        with open(nom_fichier_prive, 'wb') as f:
            f.write(key.export_key('PEM'))
        print(f"Ecriture clef privée dans {nom_fichier_prive}")

        with open(nom_fichier_public, 'wb') as f:
            f.write(self.clefPublic.export_key('PEM'))
        print(f"Ecriture clef publique dans {nom_fichier_public}")

    def chargement_clefs(self, fichier_public, fichier_prive):
        """!
        @brief Charge les clés RSA depuis des fichiers.
        @param fichier_public Fichier de la clé publique.
        @param fichier_prive Fichier de la clé privée.
        """
        self.chargement_clef_privee(fichier_prive)
        self.chargement_clef_publique(fichier_public)

    def chargement_clef_privee(self, fichier_prive):
        """!
        @brief Charge la clé privée depuis un fichier.
        @param fichier_prive Fichier contenant la clé privée.
        """
        with open(fichier_prive, 'rb') as f:
            self.clefPrive = RSA.import_key(f.read())

    def chargement_clef_publique(self, fichier_public):
        """!
        @brief Charge la clé publique depuis un fichier.
        @param fichier_public Fichier contenant la clé publique.
        """
        with open(fichier_public, 'rb') as f:
            self.clefPublic = RSA.import_key(f.read())

    def chiffrement_rsa(self, donne_claire):
        """!
        @brief Chiffre une chaîne avec la clé publique RSA.
        @param donne_claire Texte clair à chiffrer.
        @return Texte chiffré encodé en Base64.
        """
        cipher = PKCS1_OAEP.new(self.clefPublic)
        donne_claire_bytes = donne_claire.encode('utf-8')
        donne_chiffree = cipher.encrypt(donne_claire_bytes)
        return base64.b64encode(donne_chiffree).decode('utf-8')

    def dechiffrement_rsa(self, message_chiffre):
        """!
        @brief Déchiffre une chaîne RSA encodée en Base64.
        @param message_chiffre Texte chiffré en Base64.
        @return Texte clair déchiffré.
        """
        cipher = PKCS1_OAEP.new(self.clefPrive)
        donne_chiffree = base64.b64decode(message_chiffre)
        donne_claire = cipher.decrypt(donne_chiffree)
        return donne_claire.decode('utf-8')

    def chiffre_dans_fichier(self, donnee, nom_fichier):
        """!
        @brief Chiffre une chaîne et l'enregistre dans un fichier.
        @param donnee Texte à chiffrer.
        @param nom_fichier Nom du fichier de sortie.
        """
        donne_chiffree = self.chiffrement_rsa(donnee)
        with open(nom_fichier, 'w', encoding='utf-8') as f:
            f.write(donne_chiffree)
        print("Fichier enregistré avec succès.")

    def dechiffre_fichier(self, nom_fichier):
        """!
        @brief Déchiffre un fichier contenant une chaîne RSA chiffrée.
        @param nom_fichier Fichier à déchiffrer.
        @return Texte clair. Retourne "" en cas d'erreur.
        """
        try:
            with open(nom_fichier, 'r', encoding='utf-8') as f:
                message_chiffre = f.read()
            return self.dechiffrement_rsa(message_chiffre)
        except Exception as e:
            print("Erreur :", e)
            return ""

    def chiffrement_fichier(self, fichier_entree, fichier_sortie, format64=True):
        """!
        @brief Chiffre un fichier en utilisant RSA.
        @param fichier_entree Fichier source à chiffrer.
        @param fichier_sortie Fichier de sortie.
        @param format64 True pour Base64, False pour binaire.
        """
        if format64:
            with open(fichier_entree, 'r', encoding='utf-8') as f:
                texte = f.read()
            self.chiffre_dans_fichier(texte, fichier_sortie)
        else:
            cipher = PKCS1_OAEP.new(self.clefPublic)
            with open(fichier_entree, 'rb') as f_in:
                data = f_in.read()
                encrypted = cipher.encrypt(data)
            with open(fichier_sortie, 'wb') as f_out:
                f_out.write(encrypted)

    def dechiffrement_fichier(self, fichier_entree, fichier_sortie, format64=True):
        """!
        @brief Déchiffre un fichier chiffré avec RSA.
        @param fichier_entree Fichier source chiffré.
        @param fichier_sortie Fichier de sortie.
        @param format64 True si Base64, False si binaire.
        """
        if format64:
            texte = self.dechiffre_fichier(fichier_entree)
            with open(fichier_sortie, 'w', encoding='utf-8') as f:
                f.write(texte)
        else:
            cipher = PKCS1_OAEP.new(self.clefPrive)
            with open(fichier_entree, 'rb') as f_in:
                encrypted = f_in.read()
                decrypted = cipher.decrypt(encrypted)
            with open(fichier_sortie, 'wb') as f_out:
                f_out.write(decrypted)

