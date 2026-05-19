"""
Utilitaires de sécurité — Projet DevSecOps
"""
import logging
import os
import re
import sys


# ─── Version de l'application ────────────────────────────────────────────────
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")


def get_app_version() -> str:
    """Retourne la version de l'application depuis la variable d'environnement."""
    return APP_VERSION


# ─── Logger structuré ────────────────────────────────────────────────────────
def setup_logger(name: str) -> logging.Logger:
    """
    Configure et retourne un logger structuré.
    Utilise le format JSON-like pour faciliter l'intégration avec les outils SIEM.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)
    return logger


# ─── Sanitisation des entrées ────────────────────────────────────────────────
# Caractères autorisés : lettres, chiffres, espaces, tirets, apostrophes, points
_SAFE_PATTERN = re.compile(r"[^a-zA-Z0-9\sÀ-ÿ\-\_\.\,\!\?\'\"]")


def sanitize_input(value: str) -> str:
    """
    Nettoie une chaîne de caractères en supprimant les caractères potentiellement
    dangereux (XSS, injection). Principe OWASP Input Validation.

    Args:
        value: Chaîne à nettoyer

    Returns:
        Chaîne assainie

    Raises:
        ValueError: Si la valeur après nettoyage est vide
    """
    if not isinstance(value, str):
        raise TypeError(f"Attendu str, obtenu {type(value).__name__}")

    cleaned = _SAFE_PATTERN.sub("", value).strip()

    if not cleaned:
        raise ValueError("La valeur saisie est invalide ou vide après nettoyage")

    return cleaned


# ─── Validation de variables d'environnement ─────────────────────────────────
_REQUIRED_ENV_VARS = [
    # Ajouter les variables d'environnement obligatoires ici
]


def check_required_env_vars() -> dict:
    """
    Vérifie que les variables d'environnement requises sont définies.
    Retourne un dictionnaire {var: définie (bool)}.
    """
    results = {}
    for var in _REQUIRED_ENV_VARS:
        results[var] = os.getenv(var) is not None
    return results


# ─── Masquage des données sensibles dans les logs ─────────────────────────────
_SECRET_FIELDS = {"password", "token", "secret", "key", "api_key", "auth"}


def mask_sensitive(data: dict) -> dict:
    """
    Masque les valeurs sensibles dans un dictionnaire avant logging.

    Args:
        data: Dictionnaire potentiellement contenant des données sensibles

    Returns:
        Dictionnaire avec les valeurs sensibles remplacées par '***'
    """
    masked = {}
    for k, v in data.items():
        if any(secret in k.lower() for secret in _SECRET_FIELDS):
            masked[k] = "***REDACTED***"
        elif isinstance(v, dict):
            masked[k] = mask_sensitive(v)
        else:
            masked[k] = v
    return masked
