# Rôle `socle`

État minimal attendu sur toute machine du parc : paquets de base, fuseau
horaire et synchronisation de l'heure, message d'accueil, mises à jour de
sécurité appliquées automatiquement.

Ce rôle ne durcit rien et ne crée aucun compte : il rend la machine exploitable
et maintenable. Il passe avant les autres parce qu'une machine à l'heure fausse
casse silencieusement tout ce qui suit (certificats, authentifications,
corrélation de journaux).

| Système | Paquets | Horloge | Mises à jour automatiques |
|---|---|---|---|
| Debian / Ubuntu | `apt`, famille « Debian » | `systemd-timesyncd` | `unattended-upgrades` (dépôts de sécurité uniquement) |
| RHEL / Alma / Rocky | `dnf`, famille « RedHat » | `chrony` | `dnf-automatic` (`upgrade_type = security`) |

Arch Linux n'est pas pris en charge : le rôle s'arrête sur un `assert` explicite
plutôt que de ne rien faire en silence.

## Tâches exécutées

1. `assert` sur la famille d'OS (`socle_familles_supportees`).
2. Rafraîchissement du cache APT (Debian uniquement, avec validité d'une heure).
3. Installation des paquets (`socle_paquets_base` + `socle_paquets_par_famille`).
4. Fuseau horaire, puis configuration éventuelle des serveurs de temps.
5. Service d'horloge activé et démarré.
6. `/etc/motd` (message d'accueil).
7. Mises à jour de sécurité automatiques : paquet, configuration, unités activées.

## Variables

Les valeurs de repli et les dictionnaires par famille d'OS sont dans
`defaults/main.yml`. Tout est surchargeable depuis `group_vars/`.

| Variable | Défaut | Rôle |
|---|---|---|
| `socle_fuseau_horaire` | `UTC` | Fuseau de la machine (`Europe/Paris` pour un parc français) |
| `socle_paquets_base` | `[ca-certificates]` | Paquets communs à toutes les familles |
| `socle_paquets_par_famille` | voir `defaults` | Paquets par famille : `vim-tiny` (Debian), `vim-enhanced` (RedHat)… |
| `socle_cache_apt_validite` | `3600` | Validité du cache APT, en secondes |
| `socle_serveurs_ntp` | `[]` | Serveurs de temps internes. Vide = pool de la distribution |
| `socle_horloge_par_famille` | voir `defaults` | Paquet, service, fichiers et modèle d'horloge, par famille |
| `socle_motd_active` | `true` | Publier ou non `/etc/motd` |
| `socle_motd_titre`, `socle_motd_responsable`, `socle_motd_avertissement` | voir `defaults` | Contenu du message d'accueil |
| `socle_maj_auto_active` | `true` | Mises à jour de sécurité automatiques |
| `socle_maj_auto_intervalle_jours` | `1` | Fréquence de vérification (jours) |
| `socle_maj_auto_autoclean` | `false` | Purge des paquets obsolètes (désactivée : une suppression automatique peut retirer un paquet encore utilisé) |

## Gestionnaire (handler)

`Redémarre la synchronisation de l'heure` — notifié uniquement si la
configuration des serveurs de temps change. Un redémarrage, et non un
rechargement : ni `timesyncd` ni `chronyd` ne relisent leur configuration à
chaud, et croire le contraire laisse un écart entre le fichier écrit et le
service réellement appliqué.

## Exemple d'utilisation ciblée

```bash
ansible-playbook site.yml --tags socle,heure --check --diff
```
