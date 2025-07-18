
# 🔎 InfoTools Bot

**InfoTools Bot** est un bot Discord polyvalent qui fournit des outils d’analyse et d'information via des commandes simples. Il peut effectuer des recherches sur des IPs, numéros de téléphone, adresses email, domaines, et bien plus encore.

## ✨ Fonctionnalités

- `+geoip <ip>` : Donne des informations sur une adresse IP.
- `+phoneinfo <numéro>` : Affiche des détails sur un numéro de téléphone.
- `+emailinfo <email>` : Analyse et valide une adresse email.
- `+hash <texte>` : Génère plusieurs hash (MD5, SHA1, SHA256...) à partir d’un texte.
- `+base64 <encode/decode> <texte>` : Encode ou décode une chaîne en Base64.
- `+urlinfo <url>` : Analyse une URL.
- `+whois <domaine>` : Récupère les informations WHOIS d’un domaine.
- `+genpass <longueur> <symboles>` : Génère un mot de passe sécurisé.
- `+aide` : Affiche la liste des commandes disponibles.

---

## 🚀 Installation

1. Clone le repo :
   ```bash
   git clone https://github.com/votre-utilisateur/infotools-bot.git
   cd infotools-bot
````

2. Installe les dépendances :

   ```bash
   pip install -r requirements.txt
   ```

3. Configure le bot :

   * Crée un fichier `.env` ou `config.json` (selon ton implémentation) avec ton token Discord et autres configurations nécessaires.

4. Lance le bot :

   ```bash
   python bot.py
   ```

---

## ⚙️ Prérequis

* Python 3.9+
* Un bot Discord avec les permissions nécessaires (lecture, écriture, gestion des messages).

---

## 📸 Aperçu de la commande `+aide`

![Exemple d'embed d'aide](https://your-screenshot-link.png) <!-- Optionnel -->

---

## 📚 Technologies utilisées

* [discord.py](https://github.com/Rapptz/discord.py)
* API tierces pour les analyses (GeoIP, WHOIS, etc.)

---

## 🙏 Remerciements

Merci aux développeurs des API ouvertes utilisées pour les fonctionnalités du bot.
N'hésitez pas à contribuer ou à ouvrir une *issue* !

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus d'informations.


