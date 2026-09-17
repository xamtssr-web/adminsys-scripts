# Automatisation d'infrastructure — Bash & PowerShell 7

**14 scripts d'exploitation prêts pour la production** : sauvegarde, supervision, déploiement, gestion de comptes, administration Active Directory.

Chaque script suit les mêmes règles : aide complète en français, **mode simulation** (`--dry-run` / `-WhatIf`), codes retour exploitables par une supervision, journalisation horodatée, et zéro identifiant en dur. Ils sont tous vérifiés automatiquement (voir [Qualité et vérification](#qualité-et-vérification)).

> **Pourquoi ce dépôt** — en exploitation, la différence entre un incident de 5 minutes et une nuit blanche tient rarement à la compétence : elle tient à ce qui est déjà automatisé. Ces scripts sont ceux que j'utilise et que je réutilise, écrits pour être relus à 3 h du matin sans réfléchir.

---

## Scripts Bash

Clés d'exploitation : Linux (Debian/Ubuntu, Arch, Raspberry Pi OS), utilitaires standard uniquement.

| Script | Rôle | Points clés |
|---|---|---|
| [`bash/backup-rotation.sh`](bash/backup-rotation.sh) | Sauvegarde avec rotation grand-père / père / fils | Vérifie l'intégrité de l'archive après création, estime l'espace nécessaire et **refuse de démarrer** s'il est insuffisant, chiffrement `age` facultatif, manifeste SHA-256 |
| [`bash/health-check.sh`](bash/health-check.sh) | Contrôle de santé système | CPU mesuré sur 1 s (pas une moyenne instantanée), RAM, swap, disques **et inodes**, services systemd, conteneurs, endpoints HTTP, test d'écriture ; sortie **JSON** pour supervision |
| [`bash/cert-expiry-check.sh`](bash/cert-expiry-check.sh) | Expiration des certificats TLS | Certificats sur disque **et** certificats présentés par des services distants (`hote:port`, SNI géré), seuil paramétrable, sortie JSON |
| [`bash/service-watchdog.sh`](bash/service-watchdog.sh) | Surveillance et relance de services | systemd / Docker / HTTP, **limite de redémarrages par heure** (anti-boucle), historique CSV des incidents, notification webhook et/ou mail |
| [`bash/deploy-docker-stack.sh`](bash/deploy-docker-stack.sh) | Déploiement idempotent de pile Compose | `--env` obligatoire (un déploiement sans variables n'est pas reproductible), attente des *healthchecks*, **retour arrière automatique** sur le commit précédent en cas d'échec |
| [`bash/linux-user-provisioning.sh`](bash/linux-user-provisioning.sh) | Provisionnement de comptes Linux | **Idempotent** (relançable sans casser l'existant), groupes, clés SSH, `sudoers` dédié **validé par `visudo -c`**, expiration, alignement de l'existant avec `--supprimer-obsolescence` |
| [`bash/log-rotate.sh`](bash/log-rotate.sh) | Rotation de journaux applicatifs | Rotation par taille ou quotidienne, compression, rétention, purge par ancienneté, permissions et propriétaire conservés, `--copie` pour les programmes qui ne rouvrent pas leur journal |
| [`bash/lib/common.sh`](bash/lib/common.sh) | Bibliothèque commune | Journalisation, piège d'erreur avec numéro de ligne, `--dry-run`, réessais, verrou d'exécution unique (`flock`) |

### Codes retour (tous les scripts Bash)

| Code | Signification |
|---|---|
| `0` | Succès — pour `health-check.sh` : tout est OK |
| `1` | Avertissement, ou erreur d'exécution |
| `2` | Paramètres invalides, ou point critique pour les scripts de contrôle |

---

## Scripts PowerShell 7 — administration Active Directory

| Script | Rôle | Points clés |
|---|---|---|
| [`powershell/Get-ADHealthReport.ps1`](powershell/Get-ADHealthReport.ps1) | Rapport de santé de l'annuaire | Réplication entre contrôleurs, rôles FSMO, services critiques (NTDS, DNS, Netlogon, DFSR, W32Time), espace NTDS/SYSVOL, durée de vie *tombstone*, comptes dormants, stratégie de mot de passe |
| [`powershell/Test-ADHardeningBaseline.ps1`](powershell/Test-ADHardeningBaseline.ps1) | Audit de durcissement (**lecture seule**) | 11 contrôles : politique de mot de passe, verrouillage de compte, privilèges élevés (`AdminCount`, membres DA/EA/SA résolus par SID), délégation non contrainte, durée de vie Kerberos, source de temps, SMBv1, signature LDAP — statut **CONFORME / NON CONFORME / À VÉRIFIER** |
| [`powershell/New-ADBulkUsers.ps1`](powershell/New-ADBulkUsers.ps1) | Création de comptes en masse depuis CSV | Génère des mots de passe aléatoires conformes à la complexité (sans caractères ambigus type `O`/`0`), login unique dérivé et désaccentué, export des identifiants à part |
| [`powershell/New-ADUserOnboarding.ps1`](powershell/New-ADUserOnboarding.ps1) | Arrivée d'un collaborateur en une commande | Compte + groupes métier + lecteur réseau personnel (partage + ACL NTFS, héritage coupé) + mail + fiche d'accueil |
| [`powershell/Get-PasswordExpiryReport.ps1`](powershell/Get-PasswordExpiryReport.ps1) | Mots de passe arrivant à expiration | Seuil en jours, stratégie de domaine granulaire (PSO), comptes à mot de passe non expirant isolés, tri par urgence |
| [`powershell/Remove-InactiveADAccounts.ps1`](powershell/Remove-InactiveADAccounts.ps1) | Désactivation des comptes dormants | **Ne supprime jamais** : déplace en quarantaine, retire des groupes à privilèges, journal d'audit ; simulation par défaut, refus des comptes de service, `krbtgt`, RID 500 et comptes à SPN |
| [`powershell/Export-GPOBackup.ps1`](powershell/Export-GPOBackup.ps1) | Sauvegarde de toutes les stratégies de groupe | `Backup-GPO` complet, **vérifie que chaque sauvegarde est exploitable** (`Backup.xml`), manifeste CSV, archive datée, rotation des sauvegardes |

Tous les scripts destructifs utilisent `SupportsShouldProcess` : `-WhatIf` pour simuler, `-Confirm` pour valider chaque action.

---

## Prérequis

**Bash**
```bash
# Debian / Ubuntu
sudo apt install shellcheck coreutils gzip tar openssl curl
# Arch
sudo pacman -S shellcheck
# Chiffrement des sauvegardes (facultatif)
sudo apt install age
```

**PowerShell 7** — [installation](https://learn.microsoft.com/powershell/scripting/install/installing-powershell) puis :
```powershell
Install-Module ActiveDirectory   # RSAT-AD-PowerShell
Install-Module PSScriptAnalyzer  # pour le lint
```
Les scripts AD supposent une machine **membre du domaine**, avec les droits correspondants.

---

## Démarrage rapide

```bash
# Sauvegarde de /etc et /root avec rotation 24 h / 7 j / 4 sem / 6 mois
./bash/backup-rotation.sh -s /etc -s /root -d /mnt/backup

# Contrôle de santé complet, sortie JSON pour la supervision
./bash/health-check.sh --service nginx --conteneur db --http https://exemple.fr --json

# Alerte si un certificat expire dans moins de 45 jours
./bash/cert-expiry-check.sh --hote exemple.fr:443 --dossier /etc/ssl/prive --jours 45

# Rotation d'un journal dès 50 Mio, 7 archives conservées, service rechargé
./bash/log-rotate.sh --fichier /var/log/monapp/app.log --max-taille 50M --retention 7 \
    --copie --reload-service monapp
```

```powershell
# Santé de l'annuaire, export CSV
.\powershell\Get-ADHealthReport.ps1 -ExporterCsv .\sante-ad.csv

# Audit de durcissement, seulement les points à corriger
.\powershell\Test-ADHardeningBaseline.ps1 -ProblemesSeulement

# Import de 200 comptes — d'abord en simulation
.\powershell\New-ADBulkUsers.ps1 -CheminCsv .\utilisateurs.csv `
    -OUCible 'OU=Utilisateurs,DC=exemple,DC=lab' -WhatIf

# Désactivation des comptes inactifs depuis 120 jours — simulation par défaut
.\powershell\Remove-InactiveADAccounts.ps1 -JoursInactivite 120 `
    -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab'
```

Chaque script dispose de `--help` / `Get-Help` avec exemples, options et codes retour.

---

## Qualité et vérification

```bash
./tests/lint.sh                 # tout vérifier (bash + PowerShell)
./tests/lint.sh --bash          # shellcheck uniquement
./tests/lint.sh --powershell    # analyse syntaxique PowerShell uniquement
```

Ce que le dépôt garantit :

| Contrôle | Outil | État |
|---|---|---|
| Style et pièges Bash | `shellcheck -x -S style` (le niveau le plus strict, fichiers sourcés suivis) | **8/8 — 0 remarque** |
| Syntaxe PowerShell | parseur AST de PowerShell 7 | **7/7 — 0 erreur** |
| Analyse PowerShell | `PSScriptAnalyzer` | aucun `ParserError`, aucun `Error` hors `ConvertTo-SecureString` (usage légitime pour générer un mot de passe temporaire) |
| Tests fonctionnels Bash | exécution réelle : rotation de journaux, contrôle de santé sur un hôte réel, interrogation d'un certificat distant, simulation de déploiement | passés |

**Limite assumée** : les scripts PowerShell sont validés syntaxiquement et relus, mais **ne peuvent pas être exécutés sans contrôleur de domaine**. Leur comportement runtime (Backup-GPO, ACL NTFS, requêtes AD) demande un environnement Windows — je l'indique plutôt que de le sous-entendre.

---

## Conventions du dépôt

- **Mode simulation partout** : `--dry-run` côté Bash, `-WhatIf` côté PowerShell. Aucun script ne modifie un système sans qu'on le lui ait demandé explicitement.
- **Codes retour normalisés** : `0` succès · `1` avertissement ou erreur · `2` paramètres invalides ou point critique. Un script de contrôle s'intègre donc directement dans Zabbix, Centreon, Nagios ou une tâche planifiée.
- **Sorties séparées** : les données exploitables sur `stdout` (JSON, CSV), les messages humains sur `stderr` — `script --json | jq` reste toujours propre.
- **Journalisation horodatée** avec le numéro de ligne en cas d'échec (`common.sh`).
- **Détail qui coûte cher ailleurs** : la bibliothèque impose `IFS=$'\n\t'` pour la robustesse des boucles ; tout `read` qui sépare sur des espaces le fait donc explicitement (`IFS=' ' read -r`). C'est la cause d'un bug silencieux que j'ai rencontré en écrivant ces scripts — valeurs de mémoire et de disque fausses sans qu'aucune erreur ne remonte.

## Sécurité

- **Aucun secret, aucune adresse IP réelle, aucun nom de domaine ou d'organisation réel** dans le dépôt : les exemples utilisent `exemple.fr` et la plage de documentation RFC 5737 (`203.0.113.5`).
- Les mots de passe ne sont **jamais** en dur : ils sont générés aléatoirement par les scripts d'annuaire, exportés dans un fichier à détruire après communication.
- `.gitignore` protège les `.env`, `*.pem`, `*.key`, `credentials*` et les sorties de scripts.
- Les scripts de désactivation de comptes simulent par défaut et refusent de toucher aux comptes sensibles.

## Licence

MIT — voir [LICENSE](LICENSE). Réutilisation libre, attribution appréciée.

---

**Massounde CHAMSIDINE** — Administrateur systèmes, réseaux et cybersécurité
[linkedin.com/in/massounde](https://linkedin.com/in/massounde)
