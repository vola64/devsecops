# Analyse des Risques — STRIDE
## Pipeline CI/CD Sécurisé — DevSecOps

**Projet :** Sécurisation de la Supply Chain Logicielle  
**Auteur :** Pipeline CI/CD DevSecOps  
**Date :** Mai 2026  
**Méthode :** STRIDE (Microsoft Threat Modeling)

---

## 1. Introduction

L'analyse STRIDE permet d'identifier et de classifier les menaces pesant sur chaque composant du pipeline CI/CD. Chaque menace est évaluée selon sa probabilité, son impact et les contre-mesures mises en place.

### Niveaux de risque

| Niveau | Score | Description |
|--------|-------|-------------|
| 🔴 Critique | 9-10 | Compromission totale possible |
| 🟠 Élevé | 7-8  | Impact majeur sur la sécurité |
| 🟡 Moyen | 4-6  | Impact limité avec exploitation difficile |
| 🟢 Faible | 1-3  | Risque résiduel acceptable |

---

## 2. Composants analysés

```
[Dev Machine] → [GitLab Repo] → [GitLab Runner] → [Docker Hub] → [Serveur Deploy]
                     │
              [Code Source]
              [Dockerfile]
              [.gitlab-ci.yml]
```

---

## 3. Analyse STRIDE par composant

### 3.1 GitLab Repository

| ID | Catégorie STRIDE | Menace | Probabilité | Impact | Risque | Contre-mesures |
|----|-----------------|--------|-------------|--------|--------|----------------|
| T01 | **S**poofing | Usurpation d'identité d'un développeur (vol de token GitLab) | Moyen | Élevé | 🟠 Élevé | MFA GitLab, tokens courts, audit des accès |
| T02 | **T**ampering | Modification du `.gitlab-ci.yml` pour exfiltrer des secrets | Moyen | Critique | 🔴 Critique | Branch protection, code review obligatoire, CODEOWNERS |
| T03 | **R**epudiation | Pas de traçabilité des actions sur le code | Faible | Moyen | 🟡 Moyen | Audit logs GitLab, signed commits |
| T04 | **I**nfo Disclosure | Exposition de secrets dans le code (hardcoded) | Élevé | Critique | 🔴 Critique | **Gitleaks** (scan automatique), variables CI masquées |
| T05 | **D**enial of Service | Flooding de pipelines (CI abuse) | Faible | Moyen | 🟡 Moyen | Rate limiting GitLab, quotas de runners |
| T06 | **E**levation of Privilege | Runner avec permissions excessives | Moyen | Élevé | 🟠 Élevé | Runner en mode Docker, pas de privileged, least privilege |

### 3.2 Pipeline CI/CD (GitLab Runner)

| ID | Catégorie STRIDE | Menace | Probabilité | Impact | Risque | Contre-mesures |
|----|-----------------|--------|-------------|--------|--------|----------------|
| T07 | **S**poofing | Image Docker malveillante utilisée comme base | Moyen | Critique | 🔴 Critique | **Trivy scan**, images officielles uniquement, digest pinning |
| T08 | **T**ampering | Altération des artefacts entre stages | Faible | Élevé | 🟠 Élevé | Hachage des artefacts, signature Cosign |
| T09 | **I**nfo Disclosure | Secrets dans les logs CI/CD | Moyen | Élevé | 🟠 Élevé | Variables `masked`, `after_script` de nettoyage |
| T10 | **T**ampering | Injection dans le code source (SAST bypass) | Faible | Élevé | 🟡 Moyen | **Bandit + Semgrep** multi-passes, quality gates |
| T11 | **D**enial of Service | Boucle infinie dans le pipeline | Faible | Moyen | 🟢 Faible | Timeout job GitLab, `interruptible: true` |
| T12 | **E**levation of Privilege | Container escape depuis le runner | Très faible | Critique | 🟡 Moyen | Docker-in-Docker sécurisé, no `--privileged` |

### 3.3 Registre Docker Hub

| ID | Catégorie STRIDE | Menace | Probabilité | Impact | Risque | Contre-mesures |
|----|-----------------|--------|-------------|--------|--------|----------------|
| T13 | **S**poofing | Pull d'une image falsifiée (supply chain poisoning) | Moyen | Critique | 🔴 Critique | **Cosign** signature + vérification avant déploiement |
| T14 | **T**ampering | Remplacement d'une image sur Docker Hub | Faible | Critique | 🟠 Élevé | Image digest immutables, Cosign |
| T15 | **I**nfo Disclosure | Données sensibles dans les layers d'image | Moyen | Élevé | 🟠 Élevé | Multi-stage build, scan Trivy secrets |
| T16 | **D**enial of Service | Docker Hub rate limiting (pulls excessifs) | Moyen | Moyen | 🟡 Moyen | Cache Docker, miroir local |

### 3.4 Serveur de déploiement

| ID | Catégorie STRIDE | Menace | Probabilité | Impact | Risque | Contre-mesures |
|----|-----------------|--------|-------------|--------|--------|----------------|
| T17 | **S**poofing | Accès SSH non autorisé au serveur | Faible | Critique | 🟠 Élevé | Clé SSH CI/CD dédiée, `known_hosts`, fail2ban |
| T18 | **T**ampering | Modification du `docker-compose.yml` en production | Très faible | Critique | 🟡 Moyen | Déploiement automatisé uniquement via pipeline |
| T19 | **E**levation of Privilege | Container avec trop de permissions (root) | Moyen | Élevé | 🟠 Élevé | `cap_drop: ALL`, `no-new-privileges`, user 1001 |
| T20 | **I**nfo Disclosure | Variables d'environnement exposées dans les containers | Moyen | Élevé | 🟠 Élevé | `.env` non commité, secrets management |

---

## 4. Matrice de risques globale

```
Impact ↑
       │
CRITIQUE│ T04 T07│ T02 T13│
       │        │ T14 T15│
ÉLEVÉ  │ T06 T09│ T01 T08│
       │ T17 T19│ T10 T16│
MOYEN  │        │ T03 T11│
       │        │ T05 T20│
FAIBLE │        │        │
       └────────┴────────→ Probabilité
         Faible   Moyen   Élevé
```

---

## 5. Conformité OWASP Top 10 CI/CD Security Risks

| OWASP CICD Risk | Description | Contrôle implémenté |
|-----------------|-------------|---------------------|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | Branch protection + manual deploy |
| CICD-SEC-2 | Inadequate Identity and Access Management | Variables masquées, tokens CI |
| CICD-SEC-3 | Dependency Chain Abuse | Trivy + OWASP Dependency Check |
| CICD-SEC-4 | Poisoned Pipeline Execution | SAST + code review |
| CICD-SEC-5 | Insufficient PBAC | Runner scope limité |
| CICD-SEC-6 | Insufficient Credential Hygiene | Gitleaks + variables masked |
| CICD-SEC-7 | Insecure System Configuration | Dockerfile non-root, cap_drop |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services | Images officielles, digest pinning |
| CICD-SEC-9 | Improper Artifact Integrity Validation | **Cosign signature + vérification** |
| CICD-SEC-10 | Insufficient Logging and Visibility | Logs CI/CD + Prometheus/Grafana |

---

## 6. Risques résiduels

Après application de toutes les contre-mesures :

| ID | Risque résiduel | Justification |
|----|----------------|---------------|
| T12 | Container escape (🟢 Faible) | Docker-in-Docker nécessaire pour le build |
| T05 | CI abuse (🟢 Faible) | Quotas GitLab.com suffisants |
| T16 | Rate limiting (🟢 Faible) | Cache Docker réduit les pulls |

---

## 7. Plan de traitement des risques

| Priorité | Risques | Actions |
|----------|---------|---------|
| P1 (Immédiat) | T02, T04, T13 | Pipeline SAST obligatoire, Cosign déployé |
| P2 (Court terme) | T07, T08, T19 | Trivy intégré, cap_drop configuré |
| P3 (Moyen terme) | T01, T09, T17 | Audit périodique, rotation des secrets |
| P4 (Long terme) | T05, T16 | Miroir Docker, Vault pour secrets dynamiques |
