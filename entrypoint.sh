#!/bin/sh

# Créer le dossier certs s'il n'existe pas
mkdir -p certs

# Générer les certs uniquement s'ils n'existent pas déjà
if [ ! -f certs/server.key ]; then
    echo "🔑 Génération des certificats SSL auto-signés..."
    openssl req -nodes -new -x509 \
      -keyout certs/server.key \
      -out certs/server.cert \
      -days 365 \
      -subj "/CN=localhost"
else
    echo "✅ Certificats SSL déjà présents."
fi

# Lancer l'application Node.js
exec node server.js