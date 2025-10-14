# CryptoPython branche cryptoHttp 

Projet Python pour la démonstration de chiffrement (AES, RSA), de hachage, d'interface graphique, et d'une API web, avec déploiement via Docker.

## Structure du dépôt Test L

```
.
├── Dockerfile
├── docker-compose.yaml
├── README.md
├── aesgestion.py
├── hashgestion.py
├── interfaceGraphique.py
├── main_api.py
├── rsagestion.py
```

##  Description des fichiers test

- `Dockerfile` : Image Docker de l'application.
- `docker-compose.yaml` : Orchestration des conteneurs.
- `aesgestion.py` : Fonctions de chiffrement/déchiffrement AES.
- `rsagestion.py` : Fonctions RSA.
- `hashgestion.py` : Fonctions de hachage.
- `main_api.py` : API FastAPI exposant les services.
- `interfaceGraphique.py` : Interface utilisateur locale.
- `README.md` : Ce fichier.

## Lancer l’application

```bash
git clone https://github.com/PierreViland/cryptoPython.git
cd cryptoPython
git checkout cryptoHttp
docker build -t cryptoImage
docker-compose up 
```

## Exemple de routes API

- `POST /encrypt/aes`
- `POST /decrypt/aes`
- `POST /encrypt/rsa`
- `POST /decrypt/rsa`
- `POST /hash`

## Lancer l'interface graphique

```bash
python interfaceGraphique.py
```
