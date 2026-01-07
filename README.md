# 🛡️ Secure OTP & Authentication System

![NodeJS](https://img.shields.io/badge/Node.js-20-green) ![Docker](https://img.shields.io/badge/Docker-Container-blue) ![Security](https://img.shields.io/badge/Security-Hardened-red)

Projet académique de cybersécurité démontrant une implémentation robuste d'un système d'authentification à double facteur (A2F/MFA), conçu selon les principes de **Security by Design** et de **Défense en Profondeur**.

L'application est conteneurisée (Docker) et sécurisée contre les vecteurs d'attaque courants (OWASP Top 10).

## 🔒 Fonctionnalités de Sécurité

### Authentification & Session
* **Double Authentification (2FA/OTP) :** Implémentation TOTP (compatible Google Authenticator) et **Codes de Secours à usage unique** (hachés en base).
* **Gestion d'État (State Machine) :** États stricts (`Guest` -> `Partial Auth` -> `Authenticated`) empêchant le contournement du mur OTP.
* **Mots de Passe :** Hachage robuste via **Bcrypt** (Salage + Key Stretching).
* **Session :** Cookies sécurisés (`HttpOnly`, `Secure`, `SameSite: Strict`) résistants au vol de session (XSS).

### Protection Infrastructure
* **HTTPS Strict :** Chiffrement de transport TLS/SSL (Certificats auto-signés pour l'environnement dev).
* **Rate Limiting :** Protection contre les attaques par force brute sur les IPs.
* **Account Lockout :** Verrouillage automatique du compte après 5 échecs (protection contre les attaques distribuées/Botnet).
* **Audit Logging :** Journalisation structurée (JSON) des événements de sécurité via **Winston** (Connexions, échecs, changements de configuration).

### Hardening Applicatif
* **Content Security Policy (CSP) :** Configuration stricte via `Helmet` pour bloquer les injections XSS, le Clickjacking et le Sniffing MIME.
* **Sanitization :** Utilisation de requêtes préparées (`better-sqlite3`) pour neutraliser les Injections SQL.
* **Docker Isolation :** Exécution dans un conteneur Alpine Linux minimaliste, sans privilèges root inutiles, avec injection des secrets au runtime.

---

## 🚀 Installation & Démarrage (Docker)

C'est la méthode recommandée pour tester le projet.

### 1. Pré-requis
* Docker & Docker Compose installés.

### 2. Configuration de l'environnement
Copiez le fichier d'exemple et configurez vos secrets (optionnel pour le test) :

cp .env.example .env

### 3. Génération des certificats SSL (Obligatoire)
Les clés privées ne sont pas versionnées par mesure de sécurité. Vous devez générer un certificat auto-signé localement :


mkdir -p certs
openssl req -nodes -new -x509 -keyout certs/server.key -out certs/server.cert -days 365 -subj "/CN=localhost"

### 4. Lancement

docker compose up --build
L'application sera accessible sur : https://localhost:3000 (Acceptez l'avertissement de sécurité du navigateur dû au certificat auto-signé).

## 🧪 Procédures de Test (PoC)
Voici comment vérifier les mécanismes de sécurité implémentés :

**Scénario 1** : Activation A2F & Codes de Secours
Créez un compte et accédez au profil.

Cliquez sur "Activer la protection A2F", scannez le QR Code.

Notez les codes de secours affichés.

Déconnectez-vous et reconnectez-vous.

Testez l'onglet "Secours" avec un code.

Preuve : Essayez de réutiliser le même code. Il sera rejeté (Usage Unique).

**Scénario 2** : Verrouillage de Compte (Brute Force)
Tentez de vous connecter avec un mauvais mot de passe 5 fois de suite.

Résultat : Le compte est verrouillé pour 1 heure (locked_until en base).

Vérifiez les logs dans logs/security.log pour voir l'alerte de sécurité.

**Scénario 3** : Injection SQL & XSS
Tentez une injection dans le champ email : ' OR '1'='1.

Résultat : "Identifiants incorrects" (La requête préparée a neutralisé l'attaque).

Vérifiez les Headers HTTP (F12 > Network). Vous verrez Content-Security-Policy et l'absence de X-Powered-By.

## 📂 Structure du Projet
.
├── .env.example       # Modèle de configuration (SANS secrets)
├── Dockerfile         # Construction de l'image Alpine sécurisée
├── docker-compose.yml # Orchestration et montage des volumes
├── server.js          # Logique Backend (Express + Security Middleware)
├── users.db           # Base de données (Persistée via Volume Docker)
├── certs/             # Dossier des certificats (Non versionné)
├── logs/              # Dossier d'audit (Non versionné, monté via Docker)
└── public/            # Frontend (Vue.js via CDN + HTML Hardening)

## 🛠️ Stack Technique
Runtime : Node.js 20 (Alpine)

Backend : Express.js

Database : SQLite (via better-sqlite3)

Frontend : Vue.js 3 (Composition API)

Crypto : bcrypt (Passwords), otplib (2FA), OpenSSL (HTTPS)