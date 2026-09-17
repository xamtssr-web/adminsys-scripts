# Rôle `utilisateurs`

Création et alignement **idempotents** des comptes Linux depuis une liste
déclarée dans l'inventaire : comptes, groupes secondaires, clés SSH publiques,
entrées `sudoers` dédiées avec validation, expiration de compte.

La même commande sert à créer un compte et à corriger une dérive — c'est ce qui
rend l'état d'arrivée reproductible et versionnable. Aucun `useradd` n'est
lancé : un `useradd` relancé échoue ou casse le compte, et ne sait pas si le
travail était déjà fait.

## Ce que le rôle garantit

- **Aucun mot de passe en clair**, jamais : le champ `mot_de_passe_hash` reçoit
  une empreinte (`password_hash('sha512')` appliqué à une variable vaultée), et
  un compte qui n'en déclare pas est créé **verrouillé** (`password: "!"`),
  donc accessible uniquement par clé SSH ou depuis la console.
- **`sudoers` validé** : chaque fichier est contrôlé par `visudo -cf` (option
  `validate`) *avant* d'être installé, puis l'ensemble de la configuration est
  revalidé par `visudo -c` via un gestionnaire. Un fichier `sudoers` invalide
  rend `sudo` inutilisable — donc empêche toute correction ultérieure, y compris
  par Ansible.
- **Aucune suppression implicite** : rien n'est retiré sans figurer dans
  `utilisateurs_a_supprimer`, et le rôle refuse de supprimer `root` ou le compte
  de connexion utilisé par Ansible.
- **Purge des clés SSH désactivée par défaut** (`utilisateurs_cles_exclusives`) :
  écraser un `authorized_keys` retire l'accès de personnes dont on n'a pas
  forcément connaissance.

## Variables

| Variable | Défaut | Rôle |
|---|---|---|
| `utilisateurs` | `[]` | Liste des comptes à garantir (voir la structure ci-dessous) |
| `utilisateurs_groupe_sudo_par_famille` | `Debian: sudo`, `RedHat: wheel` | Groupe conférant les droits d'administration |
| `utilisateurs_coquille` | `/bin/bash` | Interpréteur par défaut |
| `utilisateurs_mot_de_passe_defaut` | `"!"` | Empreinte par défaut : compte verrouillé |
| `utilisateurs_duree_vie_mot_de_passe` | `90` | Durée de vie maximale du mot de passe (jours) |
| `utilisateurs_groupes_a_creer` | `[]` | Groupes à créer avant les comptes |
| `utilisateurs_cles_exclusives` | `false` | Retirer les clés SSH non déclarées |
| `utilisateurs_dossier_sudoers` | `/etc/sudoers.d` | Répertoire des entrées sudoers dédiées |
| `utilisateurs_valider_sudoers` | `/usr/sbin/visudo -cf %s` | Validation appliquée avant installation |
| `utilisateurs_comptes_proteges` | `[root]` | Comptes jamais supprimables |
| `utilisateurs_a_supprimer` | `[]` | Liste explicite des comptes à retirer |
| `utilisateurs_journaliser` | `true` | Trace syslog des changements d'habilitation |
| `utilisateurs_journal_facility` | `auth` | Faculté syslog utilisée pour cette trace |

### Structure d'une entrée de `utilisateurs`

```yaml
utilisateurs_liste:
  - nom: admin-secours            # obligatoire
    commentaire: "Compte de secours"
    sudo: true                    # => groupe sudo/wheel + entrée sudoers dédiée
    groupes: [adm]                # groupes secondaires supplémentaires
    coquille: /bin/bash
    cles_ssh:                     # clés PUBLIQUES uniquement, jamais la privée
      - "{{ lookup('file', 'fichiers/cles/admin-secours.pub') | trim }}"
    expiration: 2026-12-31        # compte expiré à cette date (AAAA-MM-JJ)
    uid: 1500                     # uid explicite, si nécessaire
    sudo_commandes:               # sudo restreint à ces commandes (défaut : ALL)
      - /usr/bin/systemctl restart nginx
    # mot_de_passe_hash: "{{ vault_mot_de_passe_admin | password_hash('sha512') }}"
```

L'`expiration` est saisie en `AAAA-MM-JJ` et convertie par le rôle ; l'horodatage
est ancré à midi pour qu'un décalage de fuseau ne fasse pas basculer la date
d'expiration d'un jour.

## Gestionnaires (handlers)

| Gestionnaire | Déclencheur | Effet |
|---|---|---|
| `Journalise la campagne de gestion des comptes` | compte, clé ou sudoers modifié | Trace dans syslog (`community.general.syslogger`) |
| `Valide la configuration sudoers complète` | entrée sudoers modifiée | `visudo -c`, échoue si l'ensemble est incohérent |

## Exemples

```bash
# Voir ce qui changerait, sans rien modifier
ansible-playbook site.yml --tags utilisateurs --check --diff

# N'appliquer que les comptes, sur un hôte
ansible-playbook site.yml --tags utilisateurs --limit web-01.exemple.fr
```
