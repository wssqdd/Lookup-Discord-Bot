import discord
from discord.ext import commands
import os
import asyncio
import json
import random
import datetime
import time
import ipaddress
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import re
import hashlib
import base64
import urllib.parse
import socket
import ssl
import whois
import dns.resolver
import string

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='+', intents=intents, help_command=None)

@bot.hybrid_command(name="geoip", description="Donne des informations sur une adresse IP")
async def geoip(ctx: commands.Context, ip: str):
    is_slash = ctx.interaction is not None

    # Validate IP address format
    try:
        format_ip = ipaddress.ip_address(ip)
    except ValueError:
        embed = discord.Embed(
            title="`🚫` - **Erreur**",
            description="L'adresse IP que vous avez entrée est invalide car ce n'est pas le format IPV4 ni IPV6",
            color=discord.Color.red()
        )
        embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
        return

    # Check for private/local IP addresses
    if format_ip.is_private or format_ip.is_loopback or format_ip.is_link_local:
        embed = discord.Embed(
            title="`⚠️` - **Avertissement**",
            description="Cette adresse IP est privée/locale et ne peut pas être géolocalisée.",
            color=discord.Color.orange()
        )
        embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
        return

    try:
        # Make API request with timeout
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise exception for bad status codes
        data = response.json()

        # Check if API returned an error
        if data.get('status') == 'fail':
            embed = discord.Embed(
                title="`❌` - **Erreur API**",
                description=f"Impossible de récupérer les informations: {data.get('message', 'Erreur inconnue')}",
                color=discord.Color.red()
            )
            embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
            await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
            return

        # Build description with null checks
        description_parts = [
            f"**IP:** {data.get('query', 'N/A')}",
            f"**Pays:** {data.get('country', 'N/A')}",
            f"**Région:** {data.get('regionName', 'N/A')}",
            f"**Ville:** {data.get('city', 'N/A')}",
            f"**Code Postal:** {data.get('zip', 'N/A')}",
            f"**Latitude:** {data.get('lat', 'N/A')}",
            f"**Longitude:** {data.get('lon', 'N/A')}",
            f"**Fuseau Horaire:** {data.get('timezone', 'N/A')}",
            f"**ISP:** {data.get('isp', 'N/A')}",
            f"**Organisation:** {data.get('org', 'N/A')}",
            f"**AS:** {data.get('as', 'N/A')}"
        ]

        embed = discord.Embed(
            title="`🌐` - **GeoIP**",
            description="\n".join(description_parts),
            color=0x5865F2
        )

        # Add country flag if available
        if data.get('countryCode'):
            embed.add_field(
                name="Drapeau", 
                value=f":flag_{data['countryCode'].lower()}:", 
                inline=True
            )

        embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except requests.exceptions.Timeout:
        embed = discord.Embed(
            title="`⏱️` - **Timeout**",
            description="La requête a pris trop de temps. Veuillez réessayer.",
            color=discord.Color.orange()
        )
        embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except requests.exceptions.RequestException as e:
        embed = discord.Embed(
            title="`🚫` - **Erreur de connexion**",
            description="Impossible de se connecter à l'API de géolocalisation.",
            color=discord.Color.red()
        )
        embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur inattendue**",
            description="Une erreur inattendue s'est produite.",
            color=discord.Color.red()
        )
        embed.set_footer(text=ctx.author, icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

@bot.hybrid_command(name="phoneinfo", description="Donne des informations sur un numéro de téléphone")
async def phoneinfo(ctx: commands.Context, phone_number: str):
    is_slash = ctx.interaction is not None

    try:
        # Parse le numéro de téléphone
        parsed_number = phonenumbers.parse(phone_number, None)

        # Vérifie si le numéro est valide
        if not phonenumbers.is_valid_number(parsed_number):
            embed = discord.Embed(
                title="`🚫` - **Erreur**",
                description="Le numéro de téléphone que vous avez entré n'est pas valide.",
                color=discord.Color.red()
            )
            embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
            embed.timestamp = discord.utils.utcnow()
            await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
            return

        # Obtient les informations
        country = geocoder.description_for_number(parsed_number, "fr")
        operator = carrier.name_for_number(parsed_number, "fr")
        timezones = timezone.time_zones_for_number(parsed_number)

        # Format le numéro dans différents formats
        international_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
        e164_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)

        # Détermine le type de numéro
        number_type = phonenumbers.number_type(parsed_number)
        type_mapping = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixe",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixe ou Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Numéro Vert",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Numéro Surtaxé",
            phonenumbers.PhoneNumberType.SHARED_COST: "Coût Partagé",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Numéro Personnel",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "Messagerie Vocale",
            phonenumbers.PhoneNumberType.UNKNOWN: "Inconnu"
        }
        number_type_str = type_mapping.get(number_type, "Inconnu")

        # Construit la description
        description_parts = [
            f"**Format International:** {international_format}",
            f"**Format National:** {national_format}",
            f"**Format E164:** {e164_format}",
            f"**Pays/Région:** {country or 'N/A'}",
            f"**Type:** {number_type_str}",
            f"**Opérateur:** {operator or 'N/A'}",
            f"**Code Pays:** +{parsed_number.country_code}",
            f"**Numéro National:** {parsed_number.national_number}"
        ]

        if timezones:
            timezone_str = ", ".join(timezones)
            description_parts.append(f"**Fuseaux Horaires:** {timezone_str}")

        embed = discord.Embed(
            title="`📞` - **Informations Téléphone**",
            description="\n".join(description_parts),
            color=0x5865F2
        )

        # Ajoute des informations supplémentaires
        if phonenumbers.is_possible_number(parsed_number):
            embed.add_field(
                name="Statut", 
                value="✅ Numéro possible", 
                inline=True
            )

        # Ajoute le drapeau du pays si disponible
        try:
            country_code = phonenumbers.region_code_for_number(parsed_number)
            if country_code:
                embed.add_field(
                    name="Pays", 
                    value=f":flag_{country_code.lower()}: {country_code}", 
                    inline=True
                )
        except:
            pass

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except phonenumbers.NumberParseException as e:
        error_messages = {
            phonenumbers.NumberParseException.INVALID_COUNTRY_CODE: "Code pays invalide",
            phonenumbers.NumberParseException.NOT_A_NUMBER: "Ce n'est pas un numéro de téléphone valide",
            phonenumbers.NumberParseException.TOO_SHORT_NSN: "Le numéro est trop court",
            phonenumbers.NumberParseException.TOO_SHORT_AFTER_IDD: "Le numéro est trop court après l'IDD",
            phonenumbers.NumberParseException.TOO_LONG: "Le numéro est trop long"
        }

        error_msg = error_messages.get(e.error_type, "Erreur de format du numéro")

        embed = discord.Embed(
            title="`🚫` - **Erreur de Format**",
            description=f"{error_msg}\n\n**Exemples de formats valides:**\n• +33123456789\n• +1-555-123-4567\n• 0123456789 (pour numéros français)",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur inattendue**",
            description="Une erreur inattendue s'est produite lors de l'analyse du numéro.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

# ======================== EMAIL INFO ========================
@bot.hybrid_command(name="emailinfo", description="Analyse et valide une adresse email")
async def emailinfo(ctx: commands.Context, email: str):
    is_slash = ctx.interaction is not None

    # Regex pour validation email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_regex, email):
        embed = discord.Embed(
            title="`🚫` - **Email Invalide**",
            description="L'adresse email que vous avez entrée n'est pas au bon format.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
        return

    try:
        # Sépare l'email
        local_part, domain = email.split('@')

        # Informations de base
        description_parts = [
            f"**Email:** {email}",
            f"**Partie locale:** {local_part}",
            f"**Domaine:** {domain}",
            f"**Longueur totale:** {len(email)} caractères"
        ]

        # Vérifie le domaine
        try:
            # Résolution DNS
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_list = [str(mx) for mx in mx_records]
            description_parts.append(f"**Serveurs MX:** {', '.join(mx_list[:3])}{'...' if len(mx_list) > 3 else ''}")
        except:
            description_parts.append("**Serveurs MX:** ❌ Non trouvés")

        # Détecte le type de domaine
        common_domains = {
            'gmail.com': 'Google Gmail',
            'outlook.com': 'Microsoft Outlook',
            'hotmail.com': 'Microsoft Hotmail',
            'yahoo.com': 'Yahoo Mail',
            'icloud.com': 'Apple iCloud',
            'protonmail.com': 'ProtonMail',
            'tutanota.com': 'Tutanota'
        }

        provider = common_domains.get(domain.lower(), 'Domaine personnalisé/autre')
        description_parts.append(f"**Fournisseur:** {provider}")

        # Analyse de sécurité basique
        security_checks = []
        if len(local_part) < 3:
            security_checks.append("⚠️ Partie locale très courte")
        if '+' in local_part:
            security_checks.append("📧 Utilise un alias (+)")
        if '.' in local_part:
            security_checks.append("📧 Contient des points")

        if security_checks:
            description_parts.append(f"**Observations:** {', '.join(security_checks)}")

        embed = discord.Embed(
            title="`📧` - **Analyse Email**",
            description="\n".join(description_parts),
            color=0x5865F2
        )

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.send(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur**",
            description="Erreur lors de l'analyse de l'email.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

# ======================== HASH GENERATOR ========================
@bot.hybrid_command(name="hash", description="Génère différents hash d'un texte")
async def hash_text(ctx: commands.Context, *, text: str):
    is_slash = ctx.interaction is not None

    try:
        # Génère différents hash
        md5_hash = hashlib.md5(text.encode()).hexdigest()
        sha1_hash = hashlib.sha1(text.encode()).hexdigest()
        sha256_hash = hashlib.sha256(text.encode()).hexdigest()
        sha512_hash = hashlib.sha512(text.encode()).hexdigest()

        embed = discord.Embed(
            title="`🔐` - **Générateur de Hash**",
            description=f"**Texte original:** `{text[:50]}{'...' if len(text) > 50 else ''}`",
            color=0x5865F2
        )

        embed.add_field(name="MD5", value=f"`{md5_hash}`", inline=False)
        embed.add_field(name="SHA1", value=f"`{sha1_hash}`", inline=False)
        embed.add_field(name="SHA256", value=f"`{sha256_hash}`", inline=False)
        embed.add_field(name="SHA512", value=f"`{sha512_hash[:64]}...`", inline=False)

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur**",
            description="Erreur lors de la génération des hash.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

# ======================== BASE64 ENCODER/DECODER ========================
@bot.hybrid_command(name="base64", description="Encode ou décode en Base64")
async def base64_convert(ctx: commands.Context, action: str, *, text: str):
    is_slash = ctx.interaction is not None

    if action.lower() not in ['encode', 'decode', 'enc', 'dec']:
        embed = discord.Embed(
            title="`🚫` - **Action Invalide**",
            description="Utilisez `encode` ou `decode` (ou `enc`/`dec`)",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
        return

    try:
        if action.lower() in ['encode', 'enc']:
            result = base64.b64encode(text.encode()).decode()
            title = "Encodage Base64"
        else:
            result = base64.b64decode(text.encode()).decode()
            title = "Décodage Base64"

        embed = discord.Embed(
            title=f"`🔄` - **{title}**",
            color=0x5865F2
        )

        embed.add_field(name="Entrée", value=f"`{text[:100]}{'...' if len(text) > 100 else ''}`", inline=False)
        embed.add_field(name="Résultat", value=f"`{result[:100]}{'...' if len(result) > 100 else ''}`", inline=False)

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur**",
            description="Erreur lors de la conversion Base64. Vérifiez le format.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

# ======================== URL ANALYZER ========================
@bot.hybrid_command(name="urlinfo", description="Analyse une URL")
async def urlinfo(ctx: commands.Context, url: str):
    is_slash = ctx.interaction is not None

    try:
        # Parse l'URL
        parsed = urllib.parse.urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            embed = discord.Embed(
                title="`🚫` - **URL Invalide**",
                description="L'URL doit inclure le protocole (http:// ou https://)",
                color=discord.Color.red()
            )
            embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
            embed.timestamp = discord.utils.utcnow()
            await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
            return

        description_parts = [
            f"**URL:** {url}",
            f"**Protocole:** {parsed.scheme}",
            f"**Domaine:** {parsed.netloc}",
            f"**Chemin:** {parsed.path or '/'}",
        ]

        if parsed.query:
            description_parts.append(f"**Paramètres:** {parsed.query[:50]}{'...' if len(parsed.query) > 50 else ''}")

        if parsed.fragment:
            description_parts.append(f"**Fragment:** {parsed.fragment}")

        # Vérification SSL pour HTTPS
        if parsed.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed.netloc, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                        cert = ssock.getpeercert()
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        description_parts.append(f"**SSL:** ✅ Valide jusqu'au {expiry.strftime('%d/%m/%Y')}")
            except:
                description_parts.append("**SSL:** ⚠️ Problème de certificat")

        # Test de connexion basique
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            description_parts.append(f"**Status HTTP:** {response.status_code}")
            if response.url != url:
                description_parts.append(f"**Redirection:** {response.url}")
        except:
            description_parts.append("**Status:** ❌ Inaccessible")

        embed = discord.Embed(
            title="`🔗` - **Analyse URL**",
            description="\n".join(description_parts),
            color=0x5865F2
        )

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur**",
            description="Erreur lors de l'analyse de l'URL.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

# ======================== DOMAIN WHOIS ========================
@bot.hybrid_command(name="whois", description="Informations WHOIS d'un domaine")
async def whois_lookup(ctx: commands.Context, domaine: str):
    is_slash = ctx.interaction is not None

    try:
        # Nettoie le domaine
        domain = domaine.lower().replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

        # Requête WHOIS
        w = whois.whois(domain)

        description_parts = [
            f"**Domaine:** {domain}",
            f"**Registrar:** {w.registrar or 'N/A'}",
            f"**Création:** {w.creation_date.strftime('%d/%m/%Y') if w.creation_date else 'N/A'}",
            f"**Expiration:** {w.expiration_date.strftime('%d/%m/%Y') if w.expiration_date else 'N/A'}",
            f"**Serveurs DNS:** {', '.join(w.name_servers[:3]) if w.name_servers else 'N/A'}",
        ]

        if w.org:
            description_parts.append(f"**Organisation:** {w.org}")

        if w.country:
            description_parts.append(f"**Pays:** {w.country}")

        embed = discord.Embed(
            title="`🌐` - **WHOIS Info**",
            description="\n".join(description_parts),
            color=0x5865F2
        )

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="`❌` - **Erreur WHOIS**",
            description="Impossible de récupérer les informations WHOIS pour ce domaine.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)


@bot.hybrid_command(name="genpass", description="Génère un mot de passe sécurisé")
async def generate_password(ctx: commands.Context, longueur: int = 16, symboles: bool = True):
    is_slash = ctx.interaction is not None

    if longueur < 4 or longueur > 128:
        embed = discord.Embed(
            title="🚫 Longueur invalide",
            description="La longueur doit être comprise entre 4 et 128 caractères.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)
        return

    try:
        # Définition des caractères autorisés
        minuscules = string.ascii_lowercase
        majuscules = string.ascii_uppercase
        chiffres = string.digits
        caracteres_speciaux = "!@#$%^&*()_+-=[]{}|;:,.<>?" if symboles else ""

        tous_les_caracteres = minuscules + majuscules + chiffres + caracteres_speciaux

        # Génération du mot de passe
        mot_de_passe = ''.join(random.choice(tous_les_caracteres) for _ in range(longueur))

        # Analyse de la force
        force_score = 0
        if any(c in minuscules for c in mot_de_passe):
            force_score += 1
        if any(c in majuscules for c in mot_de_passe):
            force_score += 1
        if any(c in chiffres for c in mot_de_passe):
            force_score += 1
        if symboles and any(c in caracteres_speciaux for c in mot_de_passe):
            force_score += 1
        if longueur >= 12:
            force_score += 1

        niveaux_force = {
            1: "🔴 Très faible",
            2: "🟠 Faible", 
            3: "🟡 Moyenne",
            4: "🟢 Forte",
            5: "🟢 Très forte"
        }

        force = niveaux_force.get(force_score, "🔴 Très faible")

        # Construction de l'embed
        embed = discord.Embed(
            title="🔐 Générateur de mot de passe",
            color=discord.Color.blurple()
        )
        embed.add_field(name="Mot de passe", value=f"||`{mot_de_passe}`||", inline=False)
        embed.add_field(name="Longueur", value=f"{longueur} caractères", inline=True)
        embed.add_field(name="Force estimée", value=force, inline=True)
        embed.add_field(name="Symboles inclus", value="✅ Oui" if symboles else "❌ Non", inline=True)

        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()

        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

    except Exception as e:
        embed = discord.Embed(
            title="❌ Erreur",
            description="Une erreur est survenue lors de la génération du mot de passe.",
            color=discord.Color.red()
        )
        embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
        embed.timestamp = discord.utils.utcnow()
        await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

@bot.hybrid_command(name="help", description="Affiche les commandes disponibles")
async def aide(ctx: commands.Context):
    is_slash = ctx.interaction is not None
    embed = discord.Embed(
        title="`📚` - **Aide**",
        description="Voici les commandes disponibles:",
        color=0x5865F2
    )
    embed.add_field(name="`+geoip <ip>`", value="Donne des informations sur une adresse IP", inline=False)
    embed.add_field(name="`+phoneinfo <numéro>`", value="Donne des informations sur un numéro de téléphone", inline=False)
    embed.add_field(name="`+emailinfo <email>`", value="Analyse et valide une adresse email", inline=False)
    embed.add_field(name="`+hash <texte>`", value="Génère différents hash d'un texte", inline=False)
    embed.add_field(name="`+base64 <encode/decode> <texte>`", value="Encode ou décode en Base64", inline=False)
    embed.add_field(name="`+urlinfo <url>`", value="Analyse une URL", inline=False)
    embed.add_field(name="`+whois <domaine>`", value="Informations WHOIS d'un domaine", inline=False)
    embed.add_field(name="`+genpass <longueur> <symboles>`", value="Génère un mot de passe sécurisé", inline=False)
    embed.add_field(name="`+aide`", value="Affiche les commandes disponibles", inline=False)
    embed.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar.url)
    embed.timestamp = discord.utils.utcnow()
    await ctx.reply(embed=embed, mention_author=False, ephemeral=is_slash)

@bot.event
async def on_ready():
    print(f"Connecté en tant que {bot.user.name} - {bot.user.id}")
    await bot.tree.sync()

bot.run(//TOKEN//)

  
