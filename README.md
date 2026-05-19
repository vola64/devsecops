# DevSecOps CI/CD Pipeline Sécurisé
## GitLab + Docker Hub + Cosign + Trivy

> **Projet :** Sécurisation de la Supply Chain Logicielle  
> **Stack :** Python 3.11 · FastAPI · Docker · GitLab CI/CD · Cosign · Trivy · Prometheus

---

## 📋 Vue d'ensemble

Ce projet implémente un pipeline CI/CD DevSecOps complet qui sécurise chaque étape du cycle de vie logiciel, de l'écriture du code jusqu'au déploiement en production.

### Architecture du pipeline

```
git push → GitLab CI/CD
               │
    ┌──────────┼──────────┐
    │          │          │
  SAST      Gitleaks   Semgrep
  (Bandit)   secrets    OWASP
    │
  Build (Docker multi-stage)
    │
  Tests (pytest + coverage)
    │
  Scan (Trivy + OWASP DC)
    │
  Sign (Cosign)
    │
  Push (Docker Hub)
    │
  Deploy (Docker Compose)
```

---

## 🚀 Démarrage rapide

### Prérequis

```bash
# Outils requis
docker --version          # ≥ 26.0
docker compose version    # ≥ 2.0
python3 --version         # ≥ 3.11
cosign version            # ≥ 2.0
trivy --version           # ≥ 0.51
```

### Installation locale

```bash
# 1. Cloner le projet
git clone https://gitlab.com/<votre-user>/devsecops.git
cd devsecops

# 2. Installer les dépendances Python
pip install -r requirements.txt

# 3. Lancer les tests
pytest tests/ -v --cov=src

# 4. Construire l'image
docker build -f docker/Dockerfile -t devsecops/api:local .

# 5. Scanner l'image
./scripts/scan.sh devsecops/api:local

# 6. Lancer la stack complète
docker compose up -d

# 7. Vérifier
curl http://localhost:8000/health
```

---

## 🔐 Variables CI/CD à configurer

Dans **GitLab → Settings → CI/CD → Variables** :

| Variable | Description | Masked | Protected |
|----------|-------------|--------|-----------|
| `DOCKER_USERNAME` | Nom d'utilisateur Docker Hub | ❌ | ❌ |
| `DOCKER_PASSWORD` | Token Docker Hub | ✅ | ✅ |
| `COSIGN_PRIVATE_KEY` | Clé privée Cosign (base64) | ✅ | ✅ |
| `COSIGN_PASSWORD` | Passphrase Cosign | ✅ | ✅ |
| `COSIGN_PUBLIC_KEY` | Clé publique Cosign (base64) | ❌ | ❌ |
| `DEPLOY_HOST` | IP/DNS du serveur cible | ❌ | ❌ |
| `DEPLOY_SSH_KEY` | Clé SSH pour déploiement | ✅ | ✅ |

### Générer les clés Cosign

```bash
# Générer la paire de clés
cosign generate-key-pair --output-key-prefix cosign/cosign

# Encoder en base64 pour GitLab
base64 -w 0 cosign/cosign.key  # → COSIGN_PRIVATE_KEY
base64 -w 0 cosign/cosign.pub  # → COSIGN_PUBLIC_KEY

# ⚠️ Ne jamais commiter cosign.key !
echo "cosign/cosign.key" >> .gitignore
```

---

## 📦 Structure du projet

```
devsecops/
├── .gitlab-ci.yml          # Pipeline CI/CD (7 stages)
├── README.md               # Ce fichier
├── requirements.txt        # Dépendances Python (versions fixées)
├── docker-compose.yml      # Stack de déploiement
│
├── src/
│   ├── app.py              # Application FastAPI
│   └── utils.py            # Utilitaires sécurité
│
├── tests/
│   └── test_app.py         # Tests unitaires (pytest)
│
├── docker/
│   └── Dockerfile          # Image multi-stage sécurisée
│
├── scripts/
│   ├── scan.sh             # Scan Trivy (vulnérabilités + secrets)
│   ├── sign.sh             # Signature Cosign
│   └── verify.sh           # Vérification signature
│
├── cosign/
│   └── cosign.pub          # Clé publique (à commiter)
│                           # cosign.key → JAMAIS commiter !
│
├── monitoring/
│   └── prometheus.yml      # Config Prometheus
│
└── docs/
    ├── cahier_des_charges.md   # Spécifications
    └── analyse_risques.md      # Analyse STRIDE + OWASP
```

---

## 🔍 Stages du pipeline

### Stage 1 — SAST (Analyse Statique)

| Outil | Objectif |
|-------|----------|
| **Bandit** | Détecte les vulnérabilités dans le code Python |
| **Semgrep** | Analyse OWASP Top 10, patterns dangereux |
| **Gitleaks** | Détecte les secrets/credentials dans le code |

### Stage 2 — Build

- Image **multi-stage** (builder + runtime)
- Utilisateur **non-root** (UID 1001)
- Labels OCI pour la traçabilité
- BuildKit pour le cache et la performance

### Stage 3 — Tests

```bash
pytest tests/ --cov=src --cov-fail-under=70
```

Couverture minimale : **70%**

### Stage 4 — Scan

| Outil | Cible | Seuil |
|-------|-------|-------|
| **Trivy** | Image Docker | 0 CVE CRITICAL |
| **Trivy** | Secrets dans l'image | 0 secret |
| **OWASP DC** | Dépendances Python | CVSS < 7 |

### Stage 5 — Signature (Cosign)

```bash
# Signe avec la clé privée
cosign sign --key cosign.key image:tag

# Vérifie la signature
cosign verify --key cosign.pub image:tag
```

### Stage 6 — Push

Push vers Docker Hub avec 3 tags :
- `image:$COMMIT_SHA` (immuable)
- `image:$BRANCH` (par branche)
- `image:latest` (branche main uniquement)

### Stage 7 — Deploy

- Vérification Cosign **avant** déploiement
- Docker Compose avec `cap_drop: ALL`
- Health check automatique post-déploiement

---

## 🌐 Endpoints API

| Méthode | URL | Description |
|---------|-----|-------------|
| GET | `/` | Informations API |
| GET | `/health` | Health check (pour CI/CD) |
| GET | `/items` | Liste des items |
| GET | `/items/{id}` | Récupérer un item |
| POST | `/items` | Créer un item |
| GET | `/docs` | Documentation Swagger |

---

## 📊 Monitoring

Après déploiement :

- **API** → http://localhost:8000
- **Swagger** → http://localhost:8000/docs
- **Prometheus** → http://localhost:9090
- **Grafana** → http://localhost:3000 (admin / ChangeMe123!)

---

## 🛡️ Sécurité

### Ce qui est vérifié à chaque pipeline

- ✅ Aucun secret dans le code (Gitleaks)
- ✅ Code Python sécurisé (Bandit niveau MEDIUM+)
- ✅ Patterns OWASP respectés (Semgrep)
- ✅ Aucune CVE CRITICAL dans l'image (Trivy)
- ✅ Signature cryptographique Cosign valide
- ✅ Tests passants avec couverture ≥ 70%

### Bonnes pratiques appliquées

- 🔒 Principe du **moindre privilège** (utilisateur non-root, cap_drop)
- 🔒 **Shift Left Security** (sécurité dès le développement)
- 🔒 **Supply chain integrity** (Cosign signature)
- 🔒 **Secrets management** (variables CI masquées, Gitleaks)
- 🔒 **Immutable artifacts** (tags par commit SHA)

---

## 📚 Documentation

- [Cahier des Charges](docs/cahier_des_charges.md)
- [Analyse des Risques STRIDE](docs/analyse_risques.md)

---

## 📄 Licence

MIT — Projet académique DevSecOps

---

*Projet réalisé dans le cadre du module DevSecOps — Encadrant : M. Bonitah RAMBELOSON*
