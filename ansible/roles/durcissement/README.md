# Rôle `durcissement`

Durcissement d'un serveur Linux : SSH, pare-feu, `fail2ban`, paramètres noyau,
permissions des fichiers sensibles.

C'est le seul rôle du dépôt capable de **couper l'accès** à une machine. Il est
donc écrit selon trois règles explicites.

## 1. Vérifier avant d'écrire

- Le **compte de secours** (`durcissement_utilisateur_secours`) doit exister
  dans la liste `utilisateurs` de l'inventaire et disposer de `sudo`. Sinon, le
  playbook s'arrête : durcir SSH sans accès de secours transforme une erreur de
  configuration en déplacement sur site.
- La **configuration SSH déjà en place** est testée (`sshd -t`) avant toute
  modification. Réponse en une seconde à la question « la panne vient-elle de
  nous ou était-elle là avant ? ».
- La **configuration principale inclut bien `sshd_config.d`** (`slurp` +
  `assert`). Sans cette vérification, le fichier durci serait écrit, ignoré par
  `sshd`, et le playbook afficherait un joli vert sur un serveur resté permissif.
- Couper l'authentification par mot de passe sans qu'aucune clé publique soit
  déclarée fait échouer le playbook au lieu d'enfermer l'administrateur dehors.

## 2. Ouvrir avant de fermer

- Le pare-feu autorise SSH **avant** d'être activé (`ufw` : règles puis
  `state: enabled` ; FirewallD : `permanent + immediate` sur `service: ssh`).
- La bannière SSH est écrite **avant** le fichier de configuration qui la
  référence : `sshd -t` refuse une configuration pointant vers un fichier absent.

## 3. Valider avant d'appliquer

- Chaque fichier SSH passe `validate: sshd -t -f` : un fichier invalide n'est
  jamais installé, la machine reste sur sa configuration précédente, qui
  fonctionne.
- Le gestionnaire revalide la configuration **complète** (`sshd -t`) puis
  **recharge** — il ne redémarre pas : les sessions en cours ne sont pas
  coupées. Il n'est exécuté que si un fichier a réellement changé.

## Couverture par famille d'OS

| | Debian / Ubuntu | RHEL / Alma / Rocky |
|---|---|---|
| Pare-feu | `community.general.ufw` | `ansible.posix.firewalld` |
| Service SSH | `ssh` | `sshd` |
| Action `fail2ban` | défaut de la distribution | `firewallcmd-ipset` (sans quoi les bannissements passent sous le radar de FirewallD) |
| `/etc/shadow` | `root:shadow` `0640` | `root:root` `0000` |

## Variables principales

| Variable | Défaut | Rôle |
|---|---|---|
| `durcissement_utilisateur_secours` | `""` | Compte de secours exigé avant toute modification de SSH |
| `durcissement_ssh_mot_de_passe_autorise` | `false` | Authentification par mot de passe (refusée si aucune clé n'est déclarée) |
| `durcissement_ssh_port` | `22` | Port d'écoute (le changer impose d'ouvrir la règle de pare-feu correspondante) |
| `durcissement_ssh_connexion_root` | `prohibit-password` | root par clé seulement, jamais par mot de passe |
| `durcissement_ssh_utilisateurs_autorises` | `[]` | `AllowUsers` (vide = pas de liste blanche) |
| `durcissement_ssh_groupes_autorises` | `[]` | `AllowGroups` |
| `durcissement_ssh_banniere_active` | `true` | Bannière légale avant authentification |
| `durcissement_ssh_chiffrements`, `_macs`, `_echanges` | listes modernes | Algorithmes autorisés (compatibles OpenSSH 7.4+) |
| `durcissement_pare_feu_actif` | `true` | Activer le pare-feu |
| `durcissement_pare_feu_politique_entrante` | `deny` | Politique par défaut en entrée |
| `durcissement_pare_feu_ssh_autorise` | `true` | Ouvrir SSH avant activation |
| `durcissement_pare_feu_regles` | `[]` | Règles supplémentaires (`port`, `protocole`, `commentaire`) |
| `durcissement_fail2ban_actif` | `true` | Installer et activer fail2ban |
| `durcissement_fail2ban_maxretry` / `_findtime` / `_bantime` | `5` / `10m` / `1h` | Seuils de bannissement |
| `durcissement_fail2ban_ignorer_ip` | `[]` | Adresses jamais bannies (supervision, scan interne) |
| `durcissement_fail2ban_banaction` | `""` | Action de bannissement (vide = défaut de la distribution) |
| `durcissement_sysctl` | `{}` | Paramètres noyau appliqués via `/etc/sysctl.d/99-durcissement.conf` |
| `durcissement_permissions_fichiers_par_famille` | voir `defaults` | Permissions attendues des fichiers sensibles |
| `durcissement_services_obsoletes` | `[]` | Services à arrêter et désactiver (vide : rien n'est touché) |

## Risque de verrouillage — à lire avant la première exécution

1. Jouez toujours `--check --diff` d'abord, et lisez la tâche « Écrit la
   configuration SSH durcie » : c'est là que se voit ce qui va changer.
2. Gardez une **seconde session SSH ouverte** pendant le premier passage réel :
   si la reconnexion échoue, la session ouverte permet de revenir en arrière.
3. Le compte de secours est la seule garantie prévue par ce rôle. Vérifiez-le
   explicitement : `--tags utilisateurs` puis `ssh admin-secours@hôte`.
4. Ne remplissez `durcissement_ssh_utilisateurs_autorises` qu'après avoir
   confirmé que tous les comptes nécessaires y figurent — un compte oublié perd
   l'accès immédiatement.

## Gestionnaires (handlers)

| Gestionnaire | Déclencheur | Effet |
|---|---|---|
| `Contrôle puis recharge le service SSH` | fichier de configuration ou bannière modifié | `sshd -t` puis `systemctl reload` |
| `Redémarre fail2ban` | configuration de `fail2ban` modifiée | `systemctl restart fail2ban` |
