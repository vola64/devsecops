# Cahier des Charges
## Pipeline CI/CD Sécurisé — DevSecOps

**Projet :** Sécurisation de la Supply Chain Logicielle  
**Encadrant :** M. Bonitah RAMBELOSON — Consultant DevOps | Cloud Engineer | MLOps Practitioner  
**Version :** 1.0  
**Date :** Mai 2026

---

## 1. Contexte et Problématique

### 1.1 Contexte

Les attaques sur la supply chain logicielle se multiplient et représentent une menace critique pour les organisations :

- **SolarWinds (2020)** : Compromission du pipeline de build, 18 000 organisations touchées
- **Log4Shell (2021)** : Dépendance malveillante dans des millions d'applications
- **Docker Hub poisoning** : Images Docker malveillantes téléchargées des millions de fois

Ces incidents démontrent que la sécurité ne peut plus se limiter au code applicatif — **l'ensemble de la chaîne CI/CD doit être sécurisé**.

### 1.2 Problématique

Comment garantir que le code produit par les développeurs est :
- **Intègre** : non modifié entre le commit et le déploiement ?
- **Sûr** : exempt de vulnérabilités connues et de secrets exposés ?
- **Traçable** : chaque artefact peut être lié à son origine ?
- **Conforme** : respecte les standards OWASP et les politiques de sécurité ?

---

## 2. Objectifs

### 2.1 Objectif général

Concevoir et implémenter un pipeline CI/CD DevSecOps complet intégrant la sécurité à chaque étape du cycle de vie logiciel ("Shift Left Security").

### 2.2 Objectifs spécifiques

| Objectif | Description | Critère de succès |
|----------|-------------|-------------------|
| OBJ-01 | Pipeline CI/CD automatisé | 7 stages configurés et fonctionnels |
| OBJ-02 | Analyse statique (SAST) | Bandit + Semgrep + Gitleaks intégrés |
| OBJ-03 | Scan des vulnérabilités | Trivy + OWASP DC sans CRITICAL |
| OBJ-04 | Signature des images | Cosign keyPair opérationnel |
| OBJ-05 | Gestion des secrets | Aucun secret dans le code ni les images |
| OBJ-06 | Déploiement sécurisé | Docker Compose avec least privilege |
| OBJ-07 | Analyse de risques | Modèle STRIDE documenté |
| OBJ-08 | Conformité OWASP | OWASP CICD Top 10 couvert |

---

## 3. Périmètre

### 3.1 Dans le périmètre

✅ Application Python FastAPI (API REST)  
✅ Pipeline GitLab CI/CD (7 stages)  
✅ Registre Docker Hub  
✅ Scan SAST (Bandit, Semgrep, Gitleaks)  
✅ Scan conteneur (Trivy)  
✅ Scan dépendances (OWASP Dependency Check)  
✅ Signature d'image (Cosign)  
✅ Déploiement Docker Compose sécurisé  
✅ Monitoring (Prometheus + Grafana)  
✅ Documentation (STRIDE, OWASP, rapport)

### 3.2 Hors périmètre

❌ Sécurité réseau/infrastructure (firewall, WAF)  
❌ Gestion des identités (IAM, SSO)  
❌ Sécurité applicative avancée (pen test)  
❌ Kubernetes / orchestration avancée

---

## 4. Stack Technique

### 4.1 Application

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Langage | Python | 3.11 |
| Framework API | FastAPI | 0.111.0 |
| Serveur ASGI | Uvicorn | 0.29.0 |
| Validation | Pydantic | 2.7.1 |
| Tests | pytest | 8.2.0 |

### 4.2 CI/CD et Sécurité

| Composant | Outil | Usage |
|-----------|-------|-------|
| CI/CD | GitLab CI/CD | Orchestration pipeline |
| Registre | Docker Hub | Stockage images |
| SAST Python | Bandit | Vulnérabilités code Python |
| SAST Multi | Semgrep | OWASP Top 10, patterns sécurité |
| Secrets | Gitleaks | Détection credentials dans le code |
| Scan image | Trivy | CVE dans l'image Docker |
| Scan dépendances | OWASP DC | Vulnérabilités packages Python |
| Signature | Cosign | Signature et vérification images |
| Conteneurisation | Docker + Compose | Build et déploiement |

### 4.3 Monitoring

| Composant | Outil | Usage |
|-----------|-------|-------|
| Métriques | Prometheus | Collecte métriques |
| Dashboards | Grafana | Visualisation |

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    DÉVELOPPEUR                           │
│    git commit → git push → GitLab Repository            │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              PIPELINE GITLAB CI/CD                       │
│                                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │  SAST   │→ │  BUILD  │→ │  TEST   │→ │  SCAN   │   │
│  │ Bandit  │  │ Docker  │  │ pytest  │  │  Trivy  │   │
│  │Semgrep  │  │Buildkit │  │coverage │  │  OWASP  │   │
│  │Gitleaks │  │         │  │         │  │         │   │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
│       ↓                                      ↓          │
│  ┌─────────┐                           ┌─────────┐      │
│  │  SIGN   │ ←─────────────────────── │  SCAN   │      │
│  │ Cosign  │                           │ (résult)│      │
│  └────┬────┘                           └─────────┘      │
│       │                                                  │
│  ┌────▼────┐  ┌──────────┐                             │
│  │  PUSH   │→ │  DEPLOY  │                             │
│  │ DocHub  │  │ Compose  │                             │
│  └─────────┘  └──────────┘                             │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              SERVEUR DE DÉPLOIEMENT                      │
│  ┌───────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │  FastAPI  │  │ Prometheus │  │     Grafana       │   │
│  │  :8000    │  │   :9090    │  │      :3000        │   │
│  └───────────┘  └────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 6. Exigences de sécurité

### 6.1 Exigences fonctionnelles de sécurité

| ID | Exigence | Priorité |
|----|----------|----------|
| ES-01 | Aucun secret dans le code source (Gitleaks) | Critique |
| ES-02 | Aucune vulnérabilité CRITICAL dans les images (Trivy) | Critique |
| ES-03 | Toutes les images déployées doivent être signées (Cosign) | Critique |
| ES-04 | Couverture de tests ≥ 70% | Haute |
| ES-05 | SAST sans findings HIGH+ bloquants | Haute |
| ES-06 | Utilisateur non-root dans les containers | Haute |
| ES-07 | Variables CI/CD masquées et protégées | Haute |
| ES-08 | Health check configuré sur chaque service | Moyenne |
| ES-09 | Logs structurés sans données sensibles | Moyenne |
| ES-10 | Rotation des credentials tous les 90 jours | Moyenne |

### 6.2 Exigences non-fonctionnelles

| ID | Exigence | Valeur cible |
|----|----------|--------------|
| ENF-01 | Temps d'exécution pipeline | < 15 minutes |
| ENF-02 | Disponibilité API | > 99% |
| ENF-03 | Temps de réponse API | < 200ms (p95) |
| ENF-04 | Taille de l'image Docker | < 200MB |

---

## 7. Plan de tests

### 7.1 Tests automatisés (pipeline)

| Test | Outil | Seuil de succès |
|------|-------|----------------|
| Tests unitaires | pytest | ≥ 70% couverture |
| SAST Python | Bandit | 0 finding MEDIUM+ |
| SAST multi | Semgrep | 0 finding critique |
| Secrets | Gitleaks | 0 secret détecté |
| Vulnérabilités image | Trivy | 0 CRITICAL |
| Vulnérabilités dépendances | OWASP DC | CVSS < 7 |
| Signature | Cosign | 100% images signées |

### 7.2 Tests manuels

- [ ] Vérification des dashboards Grafana
- [ ] Test de refus d'une image non signée
- [ ] Simulation d'un secret dans le code (Gitleaks doit bloquer)
- [ ] Test de l'endpoint `/health` en production

---

## 8. Livrables

| Livrable | Description | Délai |
|----------|-------------|-------|
| L01 | Code source FastAPI | Semaine 4 |
| L02 | Dockerfile sécurisé | Semaine 4 |
| L03 | Pipeline `.gitlab-ci.yml` | Semaine 6 |
| L04 | Scripts scan/sign/verify | Semaine 7 |
| L05 | Docker Compose sécurisé | Semaine 8 |
| L06 | Analyse STRIDE | Semaine 9 |
| L07 | Rapport final | Semaine 12 |
| L08 | Démonstration live | Semaine 12 |

---

## 9. Contraintes

- Budget : Utilisation de solutions open-source uniquement
- Infrastructure : Déploiement local / GitLab.com
- Conformité : OWASP CICD Security Top 10
- Documentation : En français
