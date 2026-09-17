# Automatisation d'infrastructure — Bash, PowerShell 7 & Ansible

**22 scripts et un socle Ansible complet** pour l'exploitation d'un parc : sauvegarde, supervision, correctifs, inventaire, durcissement, déploiement, administration Active Directory.

Chaque script suit les mêmes règles : aide complète en français, **mode simulation** (`--dry-run`, `-WhatIf`, `--check`), codes retour exploitables par une supervision, journalisation horodatée, et zéro identifiant en dur. Tout est vérifié automatiquement (voir [Qualité et vérification](#qualité-et-vérification)).

> **Pourquoi ce dépôt** — en exploitation, la différence entre un incident de cinq minutes et une nuit blanche tient rarement à la compétence : elle tient à ce qui était déjà automatisé. Ces scripts sont ceux que j'utilise et que je réutilise, écrits pour être relus à 3 h du matin sans réfléchir.

---

## Scripts Bash

Linux (Debian/Ubuntu, Arch, Raspberry Pi OS), utilitaires standard uniquement.

| Script | Rôle | Points clés |
|---|---|---|
| [`bash/backup-rotation.sh`](bash/backup-rotation.sh) | Sauvegarde avec rotation grand-père / père / fils | Vérifie l'intégrité après création, estime l'espace nécessaire et **refuse de démarrer** s'il manque, chiffrement `age` facultatif, manifeste SHA-256, nommage anti-collision |
| [`bash/test-backup-restore.sh`](bash/test-backup-restore.sh) | **Teste réellement une sauvegarde** en la restaurant | Restauration en dossier isolé, contrôle du nombre de fichiers, comparaison d'empreintes SHA-256, présence de fichiers obligatoires, **mesure du RTO** — et échec explicite si la sauvegarde n'est pas restaurable |
| [`bash/health-check.sh`](bash/health-check.sh) | Contrôle de santé système | CPU mesuré sur 1 s, RAM, swap, disques **et inodes**, services systemd, conteneurs, endpoints HTTP, test d'écriture ; sortie **JSON** |
| [`bash/patch-report.sh`](bash/patch-report.sh) | État des correctifs, **lecture seule** | Détecte apt/dnf/yum/pacman/zypper, compte les mises à jour (dont sécurité), repère un redémarrage requis, date la **dernière opération réelle** en lisant le contenu des journaux, sortie JSON |
| [`bash/cert-expiry-check.sh`](bash/cert-expiry-check.sh) | Expiration des certificats TLS | Certificats sur disque **et** présentés par des services distants (SNI géré), seuil paramétrable, sortie JSON |
| [`bash/inventory.sh`](bash/inventory.sh) | Inventaire complet d'un hôte | Matériel, système, CPU/RAM, disques, réseau, virtualisation, paquets, ports, services ; **JSON et CSV** pour un outil type GLPI ; chaque collecte échoue sans tuer le script |
| [`bash/audit-hardening.sh`](bash/audit-hardening.sh) | Audit de durcissement, **lecture seule stricte** | Inspiré CIS : SSH, comptes, politique de mot de passe, sudoers, pare-feu, fail2ban, SUID/SGID hors liste blanche, fichiers modifiables par tous, paramètres noyau, auditd, montages ; statut **CONFORME / NON CONFORME / À VÉRIFIER** |
| [`bash/service-watchdog.sh`](bash/service-watchdog.sh) | Surveillance et relance de services | systemd / Docker / HTTP, **limite de redémarrages par heure** (anti-boucle), historique CSV, notification webhook et/ou mail |
| [`bash/deploy-docker-stack.sh`](bash/deploy-docker-stack.sh) | Déploiement idempotent de pile Compose | `--env` obligatoire, attente des *healthchecks*, **retour arrière automatique** en cas d'échec |
| [`bash/linux-user-provisioning.sh`](bash/linux-user-provisioning.sh) | Provisionnement de comptes Linux | **Idempotent**, groupes, clés SSH, `sudoers` dédié validé par `visudo -c`, expiration, alignement de l'existant |
| [`bash/log-rotate.sh`](bash/log-rotate.sh) | Rotation de journaux applicatifs | Rotation par taille ou quotidienne, compression, rétention, purge par ancienneté, permissions conservées, `--copie` pour les programmes qui ne rouvrent pas leur journal |
| [`bash/lib/common.sh`](bash/lib/common.sh) | Bibliothèque commune | Journalisation, piège d'erreur avec numéro de ligne, mode simulation, réessais, verrou d'exécution unique |

### Codes retour (tous les scripts Bash)

| Code | Signification |
|---|---|
| `0` | Succès — pour les scripts de contrôle : tout est conforme |
| `1` | Avertissement, ou erreur d'exécution |
| `2` | Paramètres invalides, ou point critique pour les scripts de contrôle |

---

## Scripts PowerShell 7 — administration Active Directory et parc Windows

| Script | Rôle | Points clés |
|---|---|---|
| [`powershell/Get-ADHealthReport.ps1`](powershell/Get-ADHealthReport.ps1) | Rapport de santé de l'annuaire | Réplication entre contrôleurs, rôles FSMO, services critiques, espace NTDS/SYSVOL, durée de vie *tombstone*, comptes dormants, stratégie de mot de passe |
| [`powershell/Test-ADHardeningBaseline.ps1`](powershell/Test-ADHardeningBaseline.ps1) | Audit de durcissement (**lecture seule**) | 11 contrôles : politique de mot de passe, verrouillage, privilèges élevés résolus par SID, délégation non contrainte, Kerberos, source de temps, SMBv1, signature LDAP |
| [`powershell/New-ADUserOnboarding.ps1`](powershell/New-ADUserOnboarding.ps1) | Arrivée d'un collaborateur en une commande | Compte + groupes métier + lecteur réseau personnel (partage + ACL NTFS) + mail + fiche d'accueil |
| [`powershell/Invoke-ADUserOffboarding.ps1`](powershell/Invoke-ADUserOffboarding.ps1) | Départ d'un collaborateur | Désactivation (**jamais de suppression**), export des appartenances avant modification, retrait des groupes, mise en quarantaine, messagerie, journal d'audit et fiche de sortie ; **refuse** les comptes à privilèges, `krbtgt`, RID 500 et comptes à SPN |
| [`powershell/New-ADBulkUsers.ps1`](powershell/New-ADBulkUsers.ps1) | Création de comptes en masse depuis CSV | Mots de passe aléatoires conformes à la complexité (sans caractères ambigus), login unique dérivé et désaccentué, export séparé |
| [`powershell/Remove-InactiveADAccounts.ps1`](powershell/Remove-InactiveADAccounts.ps1) | Comptes dormants | Déplace en quarantaine, retire des groupes à privilèges, journal d'audit ; **simulation par défaut** |
| [`powershell/Get-PasswordExpiryReport.ps1`](powershell/Get-PasswordExpiryReport.ps1) | Mots de passe à renouveler | Seuil en jours, stratégies granulaires (*PSO*), tri par urgence |
| [`powershell/Export-GPOBackup.ps1`](powershell/Export-GPOBackup.ps1) | Sauvegarde des stratégies de groupe | `Backup-GPO` complet, **vérification que chaque sauvegarde est exploitable**, manifeste CSV, archive datée, rotation |
| [`powershell/Test-BackupRestore.ps1`](powershell/Test-BackupRestore.ps1) | **Test réel de restauration** (Windows) | Extraction en dossier isolé, empreintes SHA-256 comparées au manifeste, fichiers obligatoires, **mesure du RTO**, nettoyage systématique |
| [`powershell/Get-PatchComplianceReport.ps1`](powershell/Get-PatchComplianceReport.ps1) | Conformité des correctifs du parc | Correctifs installés et date du dernier, mises à jour en attente (API Windows Update), indicateurs de redémarrage (CBS, WU, SCCM), fraîcheur des signatures antivirus ; local et distant |
| [`powershell/Get-InfrastructureInventory.ps1`](powershell/Get-InfrastructureInventory.ps1) | Inventaire du parc Windows | Matériel, système, disques, réseau, virtualisation, logiciels (lus dans la base de désinstallation — **jamais** `Win32_Product`, qui reconfigure les MSI installés) ; CSV et JSON |

Tous les scripts destructifs utilisent `SupportsShouldProcess` : `-WhatIf` pour simuler, `-Confirm` pour valider chaque action.

---

## Socle Ansible

Trois rôles idempotents, un inventaire d'exemple et des modèles de configuration.

```
ansible/
├── ansible.cfg                      # configuration, inventaire par défaut, sortie lisible
├── site.yml                         # orchestration : socle → utilisateurs → durcissement
├── collections/requirements.yml
├── inventories/exemple/
│   ├── hosts.yml                    # groupes serveurs_web / serveurs_bdd
│   └── group_vars/tous.yml          # toutes les variables, commentées
└── roles/
    ├── socle/                       # paquets de base, fuseau horaire et NTP, motd, mises à jour de sécurité auto
    ├── utilisateurs/                # comptes, clés SSH, sudoers validé, expiration — depuis une simple liste
    └── durcissement/                # SSH durci, pare-feu, fail2ban, sysctl, permissions sensibles
```

| Rôle | Tâches | Variables | Modèles |
|---|---|---|---|
| `socle` | 147 lignes | 108 | 5 |
| `utilisateurs` | 199 lignes | 92 | 1 |
| `durcissement` | 366 lignes | 270 | 3 |

Principes tenus : **aucun module `command`/`shell`** quand un module existe (l'idempotence est réelle, pas théorique), gestion Debian et RedHat/Alma/Rocky via `ansible_os_family`, tags pour rejouer une seule couche, aucun secret en clair (mots de passe par `password_hash` ou coffre), et un utilisateur de secours documenté pour que le durcissement SSH ne puisse pas couper l'accès.

```bash
cd ansible
ansible-playbook -i inventories/exemple/hosts.yml site.yml --check --diff   # simulation d'abord
ansible-playbook -i inventories/exemple/hosts.yml site.yml --tags durcissement
```

---

## Démarrage rapide

```bash
# Sauvegarder, puis PROUVER que la sauvegarde est restaurable
./bash/backup-rotation.sh -s /etc -s /home -d /mnt/backup
./bash/test-backup-restore.sh --archive /mnt/backup/sauvegarde_*.tar.gz \
    --fichier-attendu etc/ssh/sshd_config --rto-max 900

# État réel d'un serveur : santé, correctifs, durcissement, inventaire
./bash/health-check.sh --service nginx --conteneur db --http https://exemple.fr --json
./bash/patch-report.sh --json --max-retard 30
./bash/audit-hardening.sh --problemes-seulement
./bash/inventory.sh --json --csv-fichier inventaire.csv
```

```powershell
# Annuaire et parc
.\powershell\Get-ADHealthReport.ps1 -ExporterCsv .\sante-ad.csv
.\powershell\Get-PatchComplianceReport.ps1 -ComputerName SRV-DC1, SRV-FIC1 -ExporterCsv .\correctifs.csv
.\powershell\Test-ADHardeningBaseline.ps1 -ProblemesSeulement
.\powershell\Get-InfrastructureInventory.ps1 -InclureLogiciels -ExporterJson .\parc.json

# Cycle de vie d'un collaborateur — toujours en simulation d'abord
.\powershell\New-ADUserOnboarding.ps1 -Prenom Jean -Nom Dupont -Service Informatique `
    -OUCible 'OU=Utilisateurs,DC=exemple,DC=lab' -WhatIf
.\powershell\Invoke-ADUserOffboarding.ps1 -Identite j.dupont `
    -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab' -WhatIf

# Et la preuve que la sauvegarde vaut quelque chose
.\powershell\Test-BackupRestore.ps1 -Archive \\nas\sauvegardes\serveur-01.tar.gz `
    -ManifesteCsv .\manifeste.csv -RtoMaxSecondes 900
```

Chaque script dispose de `--help` / `Get-Help` avec exemples, options et codes retour.

---

## Qualité et vérification

```bash
./tests/lint.sh                 # tout vérifier (Bash + PowerShell)
./tests/lint.sh --bash
./tests/lint.sh --powershell
```

| Contrôle | Outil | Résultat |
|---|---|---|
| Style et pièges Bash | `shellcheck -x -S style` (niveau le plus strict, fichiers sourcés suivis) | **11/11 scripts — 0 remarque** |
| Syntaxe PowerShell | parseur AST de PowerShell 7 | **11/11 scripts — 0 erreur** |
| Analyse PowerShell | `PSScriptAnalyzer` | aucun `ParserError`, aucune erreur hors usage légitime de `ConvertTo-SecureString` pour générer un mot de passe temporaire |
| Rôles Ansible | `ansible-lint` | **0 échec, 0 avertissement — profil *production*** |
| Syntaxe des playbooks | `ansible-playbook --syntax-check` | passe |
| Exécution réelle (Bash) | sur **Debian 12 et Debian 13**, deux machines différentes | les 11 scripts : `--help` → 0, option inconnue → 2, sorties JSON valides |
| Restauration de sauvegarde | archive saine → code 0 · archive tronquée → **code 2** | vérifié |

### Ce que les tests croisés ont révélé

Tester sur un second système n'est pas un luxe. Trois défauts réels ont été trouvés uniquement parce que les scripts ont tourné ailleurs que sur leur machine de développement :

| Défaut | Cause | Correction |
|---|---|---|
| Sauvegarde impossible en simulation | `df` appelé sur un dossier de destination pas encore créé → arrêt du script | mesure sur l'ancêtre existant, tolérance si `df` échoue |
| Deux sauvegardes dans la même minute se détruisaient | détection de collision testant `.gz` au lieu de `.tar.gz` → `gzip` refusait d'écraser et laissait un `.tar` orphelin | nom unique calculé sur **tous** les fichiers dérivés |
| Date de dernière mise à jour fausse | lecture de la date de modification d'un journal **vide** (date de rotation, pas d'installation) | lecture du **contenu** des journaux, repli explicite et signalé comme approximatif |

**Limite assumée** : les scripts PowerShell sont validés syntaxiquement et relus, mais **ne peuvent pas être exécutés sans contrôleur de domaine ni machine Windows**. Leur comportement runtime (`Backup-GPO`, ACL NTFS, requêtes AD) demande un environnement Windows — je l'indique plutôt que de le sous-entendre.

---

## Conventions du dépôt

- **Mode simulation partout** : `--dry-run`, `-WhatIf`, `--check`. Aucun script ne modifie un système sans qu'on le lui ait demandé explicitement.
- **Codes retour normalisés** : `0` succès · `1` avertissement ou erreur · `2` paramètres invalides ou point critique. Un script de contrôle s'intègre directement dans Zabbix, Centreon, Nagios, un playbook ou une tâche planifiée.
- **Sorties séparées** : les données exploitables sur `stdout` (JSON, CSV), les messages humains sur `stderr` — `script --json | jq` reste toujours propre.
- **Journalisation horodatée** avec le numéro de ligne en cas d'échec.
- **Détail qui coûte cher ailleurs** : la bibliothèque impose `IFS=$'\n\t'` pour la robustesse des boucles ; tout `read` qui sépare sur des espaces le fait donc explicitement (`IFS=' ' read -r`). C'est la cause d'un bug silencieux rencontré en écrivant ces scripts — valeurs de mémoire et de disque fausses, sans qu'aucune erreur ne remonte.

## Sécurité

- **Aucun secret, aucune adresse IP réelle, aucun nom de domaine ou d'organisation réel** : les exemples utilisent `exemple.fr` et la plage de documentation RFC 5737 (`203.0.113.5`).
- Les mots de passe ne sont **jamais** en dur : générés aléatoirement par les scripts d'annuaire, exportés dans un fichier à détruire après communication.
- `.gitignore` protège les `.env`, `*.pem`, `*.key`, `credentials*` et les sorties de scripts.
- Les scripts de désactivation de comptes simulent par défaut et refusent de toucher aux comptes sensibles.

## Licence

MIT — voir [LICENSE](LICENSE). Réutilisation libre, attribution appréciée.

---

**Massounde CHAMSIDINE** — Administrateur systèmes, réseaux et cybersécurité
[linkedin.com/in/massounde](https://linkedin.com/in/massounde)
