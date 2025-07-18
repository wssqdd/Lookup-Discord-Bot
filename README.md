# 🔎 InfoTools Bot

**InfoTools Bot** est un bot Discord polyvalent qui fournit des outils d’analyse et d'information via des commandes simples. Il permet d’effectuer des recherches sur des IPs, numéros de téléphone, adresses email, domaines, et bien plus encore.

---

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

1. **Clone le repo** :
   ```bash
   git clone https://github.com/votre-utilisateur/infotools-bot.git
   cd infotools-bot
````

2. **Installe les dépendances** :

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure le bot** :
   Crée un fichier `.env` ou `config.json` (selon ton implémentation) contenant :

   * Le token du bot Discord
   * Les clés API nécessaires (facultatif selon les fonctionnalités)

4. **Lance le bot** :

   ```bash
   python bot.py
   ```

---

## ⚙️ Prérequis

* Python 3.9 ou supérieur
* Un bot Discord configuré avec les permissions suivantes :

  * Lire les messages
  * Envoyer des messages
  * Intégrer des liens
  * Utiliser les commandes slash (si applicable)

---

## 📸 Aperçu de la commande `+aide`

> *(Ajoute ici une capture d’écran de l’embed si disponible)*
> ![Exemple d'embed d'aide](https://your-screenshot-link.png)

---

## 📚 Technologies utilisées

* [discord.py](https://github.com/Rapptz/discord.py)
* API tierces pour l’analyse d’IP, WHOIS, etc.
* Python standard (`hashlib`, `base64`, etc.)

---

## 🙏 Remerciements

Merci aux développeurs et contributeurs des API ouvertes utilisées dans ce projet.
Les contributions sont les bienvenues : bugs, suggestions, améliorations...

---

## 📄 Licence

Ce projet est sous licence **MIT**.
Voir le fichier [LICENSE](LICENSE) pour plus d’informations.

```



