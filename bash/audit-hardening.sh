#!/usr/bin/env bash
# =============================================================================
# audit-hardening.sh — Audit de durcissement d'un serveur Linux (inspiré CIS)
# -----------------------------------------------------------------------------
# Passe en revue les points qui font la différence entre un serveur posé sur le
# réseau et un serveur administré : accès SSH, comptes, politique de mot de
# passe, sudo, pare-feu, fail2ban, mises à jour automatiques, binaires SUID,
# permissions critiques, services exposés, paramètres noyau, synchronisation
# horaire, auditd, options de montage et accès console.
#
# Pourquoi : un audit manuel de durcissement se fait une fois puis s'oublie — et
# une mise à jour applicative réactive un réglage qu'on avait pris soin de
# fermer. Ce script rejoue le contrôle en quelques secondes, sans agent, sans
# dépendance et sans rien modifier, pour servir de rapport avant/après et de
# garde-fou avant une mise en production.
#
# LECTURE SEULE STRICTE : le script ne modifie ni fichier, ni service, ni
# paramètre noyau. Il lit /proc, /sys, /etc, et les commandes de consultation
# (ss, systemctl status, ufw status, nft list, iptables -S). Les remédiations
# sont affichées sous forme de recommandations, jamais appliquées.
#
# Codes retour :
#   0 = conforme (aucun écart sur les contrôles exécutés)
#   1 = écarts mineurs (non-conformités non critiques ou points à vérifier)
#   2 = écarts critiques (non-conformité sur un contrôle de criticité élevée)
#
# Exemples :
#   ./audit-hardening.sh
#   ./audit-hardening.sh --problemes-seulement
#   ./audit-hardening.sh --niveau 2 --rapport /var/tmp/audit-$(hostname).txt
#   ./audit-hardening.sh --json | jq '.controles[] | select(.statut != "CONFORME")'
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# --- Valeurs par défaut ------------------------------------------------------
VERSION_SCRIPT="1.0.0"
FORMAT="texte"          # texte | json
RAPPORT=""
PROBLEMES=0             # 1 = n'afficher que les non-conformités et à vérifier
NIVEAU=1                # niveau CIS : 1 (socle) ou 2 (durcissement renforcé)

# Un contrôle par entrée, au format :
#   id<TAB>niveau<TAB>criticité<TAB>statut<TAB>titre<TAB>détail<TAB>recommandation
CONTROLES=()
NB_CONFORME=0
NB_NON_CONFORME=0
NB_A_VERIFIER=0
NB_CRITIQUES=0          # non-conformités de criticité élevée -> code retour 2

# Binaires SUID/SGID légitimes sur une Debian/Ubuntu standard. Tout ce qui n'est
# pas dans cette liste est signalé : c'est précisément le but du contrôle.
LISTE_BLANCHE_SUID=(
    su mount umount passwd chsh chfn gpasswd newgrp sudo pkexec
    ssh-keysign dbus-daemon-launch-helper polkit-agent-helper-1
    unix_chkpwd pam_extrausers_chkpwd utempter fusermount fusermount3
    mount.nfs mount.cifs ntfs-3g exim4 ping snap-confine chrome-sandbox
    cockpit-session auth_pam_tool vmware-user-suid-wrapper Xorg pppd
)
LISTE_BLANCHE_SGID=(
    crontab chage expiry ssh-agent wall write tty bsd-write dotlockfile
    unix_chkpwd pam_extrausers_chkpwd utempter mlocate locate postdrop
    postqueue screen sudo w3mimgdisplay
)

usage() {
    entete_script "Audit de durcissement d'un serveur Linux, en lecture seule (inspiré CIS)."
    cat >&2 <<'EOF'

Usage :
  audit-hardening.sh [options]

Options :
      --niveau <1|2>             Niveau CIS à contrôler (défaut : 1).
                                 Le niveau 2 ajoute les contrôles renforcés.
      --json                     Sortie JSON sur stdout
      --rapport <fichier>        Écrit en plus le rapport texte dans ce fichier
      --problemes-seulement      N'affiche que les NON CONFORME et À VÉRIFIER
  -n, --dry-run                  Accepté sans effet : ce script ne modifie
                                 jamais le système (lecture seule stricte)
  -q, --quiet                    N'affiche que le résumé (les contrôles restent
                                 présents dans le rapport et le JSON)
  -v, --verbose                  Journalise le détail des lectures sur stderr
  -h, --help                     Affiche cette aide

Codes retour :
  0  conforme : aucun écart sur les contrôles exécutés
  1  écarts mineurs : non-conformité non critique, ou point à vérifier
  2  écarts critiques : non-conformité sur un contrôle de criticité élevée
     (accès SSH de root, comptes sans mot de passe, pare-feu inactif…)

Exemples :
  audit-hardening.sh --problemes-seulement
  audit-hardening.sh --niveau 2 --rapport /var/tmp/audit-serveur.txt
  audit-hardening.sh --json | jq '.resume'

Notes :
  Audit non intrusif et heuristique : il lit les fichiers de configuration et
  /proc sans se connecter ni tester les services. Un réglage appliqué par le
  serveur SSH via un bloc « Match » n'est pas interprété. Il ne remplace pas un
  outil de référence (CIS-CAT, Lynis) mais sert de première passe reproductible.
  Le filtre --problemes-seulement s'applique aux sorties ; le résumé et le code
  retour portent, eux, sur l'ensemble des contrôles exécutés.
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --niveau)                 NIVEAU="${2:?}"; shift 2 ;;
        --json)                   FORMAT="json"; shift ;;
        --rapport)                RAPPORT="${2:?}"; shift 2 ;;
        --problemes-seulement)    PROBLEMES=1; shift ;;
        -n|--dry-run)             shift ;;
        -q|--quiet)               QUIET=1; shift ;;
        -v|--verbose)             VERBOSE=1; shift ;;
        -h|--help)                usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

if [[ ! "$NIVEAU" =~ ^[12]$ ]]; then
    die_usage "--niveau attend 1 ou 2 (reçu : ${NIVEAU})"
fi

if [[ -n "$RAPPORT" ]]; then
    if [[ -d "$RAPPORT" ]]; then
        die_usage "--rapport attend un fichier, pas un répertoire : ${RAPPORT}"
    fi
    repertoire_rapport="$(dirname "$RAPPORT")"
    if [[ ! -d "$repertoire_rapport" ]]; then
        die "Répertoire du rapport inexistant : ${repertoire_rapport}"
    fi
    if [[ ! -w "$repertoire_rapport" ]]; then
        die "Répertoire du rapport non inscriptible : ${repertoire_rapport}"
    fi
fi

init_script "" ""

# -----------------------------------------------------------------------------
# Outils de lecture (aucune commande modifiante)
# -----------------------------------------------------------------------------

# Lecture tolérante : renvoie une chaîne vide si le fichier est absent ou
# illisible. Indispensable sous set -e, où une lecture non protégée ferait
# sortir le script au milieu de l'audit.
lire_fichier() {
    local chemin="$1"
    if [[ -r "$chemin" ]]; then
        head -n 1 "$chemin" 2>/dev/null | tr -d '\n\r\000' || true
    fi
}

# Commande de consultation : son échec ne doit jamais arrêter l'audit.
lire_cmd() {
    "$@" 2>/dev/null || true
}

# Paramètre noyau lu depuis /proc/sys (évite de dépendre de la commande sysctl)
lire_sysctl() {
    local parametre="$1"
    lire_fichier "/proc/sys/${parametre//./\/}"
}

# Enregistre un contrôle. L'ordre des arguments suit celui de la ligne affichée :
#   controle <id> <niveau> <criticité> <statut> <titre> <détail> <recommandation>
# criticité : elevee (une non-conformité est critique) ou normale
# statut     : CONFORME | NON_CONFORME | A_VERIFIER
controle() {
    local id="$1" niveau="$2" criticite="$3" statut="$4"
    local titre="$5" detail="$6" recommandation="$7"

    if (( niveau > NIVEAU )); then
        return 0
    fi

    # Les tabulations servent de séparateur interne : on les neutralise.
    titre="${titre//$'\t'/ }"
    detail="${detail//$'\t'/ }"
    recommandation="${recommandation//$'\t'/ }"
    CONTROLES+=("${id}"$'\t'"${niveau}"$'\t'"${criticite}"$'\t'"${statut}"$'\t'"${titre}"$'\t'"${detail}"$'\t'"${recommandation}")

    case "$statut" in
        CONFORME)
            (( NB_CONFORME++ )) || true
            ;;
        NON_CONFORME)
            (( NB_NON_CONFORME++ )) || true
            if [[ "$criticite" == "elevee" ]]; then
                (( NB_CRITIQUES++ )) || true
            fi
            ;;
        *)
            (( NB_A_VERIFIER++ )) || true
            ;;
    esac
    log_debug "contrôle ${id} : ${statut}"
}

# Contrôle générique d'un paramètre noyau : plusieurs valeurs acceptées,
# séparées par un tube (ex. « 0|1 »). Un paramètre absent est signalé comme
# « à vérifier » plutôt que conforme à tort.
controle_sysctl() {
    local id="$1" niveau="$2" criticite="$3" parametre="$4" attendues="$5"
    local titre="$6" recommandation="$7"
    local valeur statut detail valeur_attendue correspond

    valeur="$(lire_sysctl "$parametre")"
    if [[ -z "$valeur" ]]; then
        controle "$id" "$niveau" "$criticite" "A_VERIFIER" "$titre" \
            "${parametre} : paramètre absent de /proc/sys" "$recommandation"
        return 0
    fi

    correspond=0
    IFS='|' read -r -a liste_attendues <<< "$attendues"
    for valeur_attendue in "${liste_attendues[@]}"; do
        if [[ "$valeur" == "$valeur_attendue" ]]; then
            correspond=1
        fi
    done

    if (( correspond )); then
        statut="CONFORME"
        detail="${parametre} = ${valeur}"
    else
        statut="NON_CONFORME"
        detail="${parametre} = ${valeur} (attendu : ${attendues//|/ ou })"
    fi
    controle "$id" "$niveau" "$criticite" "$statut" "$titre" "$detail" "$recommandation"
}

# Options de montage d'un point de montage, vide s'il n'est pas monté à part
options_montage() {
    local point="$1"
    awk -v p="$point" '$2 == p { print $4; exit }' /proc/mounts 2>/dev/null || true
}

# Tronque une liste « a, b, c » au-delà de N éléments : un rapport reste
# exploitable même quand l'hôte expose soixante ports.
tronquer_liste() {
    local liste="$1" maximum="$2" nombre
    nombre="$(printf '%s' "$liste" | awk -F', ' '{ print NF }')"
    if (( nombre > maximum )); then
        printf '%s, … (+%d autres)' \
            "$(printf '%s' "$liste" | awk -v m="$maximum" -F', ' '
                { for (i = 1; i <= m; i++) printf "%s%s", (i > 1 ? ", " : ""), $i }')" \
            "$(( nombre - maximum ))"
    else
        printf '%s' "$liste"
    fi
}

# Directives du serveur SSH : le dernier fichier lu gagne, comme le fait sshd
# (sshd_config puis /etc/ssh/sshd_config.d/*.conf).
sshd_directive() {
    local directive="$1" fichier ligne valeur=""
    for fichier in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -r "$fichier" ]] || continue
        while IFS= read -r ligne; do
            ligne="${ligne%%#*}"
            if [[ "$ligne" =~ ^[[:space:]]*${directive}[[:space:]]+([^[:space:]]+) ]]; then
                valeur="${BASH_REMATCH[1]}"
            fi
        done < "$fichier"
    done
    printf '%s' "$valeur"
}

# Valeur d'une directive de /etc/login.defs
login_defs() {
    local directive="$1"
    if [[ -r /etc/login.defs ]]; then
        awk -v c="$directive" '$1 == c { print $2; exit }' /etc/login.defs 2>/dev/null || true
    fi
}

# Un module PAM est-il activé (ligne non commentée) dans l'un des fichiers ?
pam_actif() {
    local module="$1"; shift
    local fichier
    for fichier in "$@"; do
        [[ -r "$fichier" ]] || continue
        if grep -qE "^[[:space:]]*[^#[:space:]].*${module}" "$fichier" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Permissions d'un fichier au format « 640 root:shadow »
permissions_fichier() {
    local chemin="$1"
    if [[ -e "$chemin" ]]; then
        stat -c '%a %U:%G' "$chemin" 2>/dev/null || true
    fi
}

# -----------------------------------------------------------------------------
# Contexte de la machine
# -----------------------------------------------------------------------------
HOTE_COURT="$(lire_cmd hostname)"
DISTRIBUTION="$(awk -F= '$1 == "PRETTY_NAME" { gsub(/^"|"$/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true)"
if [[ -z "$DISTRIBUTION" ]]; then
    DISTRIBUTION="$(lire_cmd uname -s)"
fi

# -----------------------------------------------------------------------------
# 1. Serveur SSH
# -----------------------------------------------------------------------------
log_step "Serveur SSH"
FICHIERS_SSH=()
for fichier in /etc/ssh/sshd_config.d/*.conf; do
    [[ -r "$fichier" ]] || continue
    FICHIERS_SSH+=("$fichier")
done
if [[ ${#FICHIERS_SSH[@]} -gt 0 ]]; then
    log_debug "fichiers de configuration SSH additionnels : ${FICHIERS_SSH[*]}"
fi

if [[ ! -r /etc/ssh/sshd_config ]]; then
    controle "SSH-00" 1 normale "A_VERIFIER" "Configuration du serveur SSH" \
        "/etc/ssh/sshd_config est absent ou illisible" \
        "Installer et configurer openssh-server si un accès distant est nécessaire"
else
    valeur="$(sshd_directive PermitRootLogin)"
    case "$valeur" in
        no)  statut="CONFORME";      detail="PermitRootLogin no" ;;
        "")  statut="A_VERIFIER";    detail="directive absente : sshd applique sa valeur par défaut (prohibit-password)" ;;
        *)   statut="NON_CONFORME";  detail="PermitRootLogin ${valeur}" ;;
    esac
    controle "SSH-01" 1 elevee "$statut" "Connexion directe de root en SSH" \
        "$detail" "Définir « PermitRootLogin no » et administrer via sudo et un compte nominatif"

    valeur="$(sshd_directive PasswordAuthentication)"
    case "$valeur" in
        no)  statut="CONFORME";      detail="PasswordAuthentication no (authentification par clé)" ;;
        "")  statut="A_VERIFIER";    detail="directive absente : sshd applique sa valeur par défaut (yes)" ;;
        *)   statut="NON_CONFORME";  detail="PasswordAuthentication ${valeur}" ;;
    esac
    controle "SSH-02" 1 elevee "$statut" "Authentification par mot de passe SSH" \
        "$detail" "Définir « PasswordAuthentication no » et distribuer des clés SSH"

    valeur="$(sshd_directive Port)"
    if [[ -z "$valeur" ]]; then
        statut="NON_CONFORME"; detail="directive absente : port par défaut 22"
    elif [[ "$valeur" == "22" ]]; then
        statut="NON_CONFORME"; detail="Port ${valeur} (port par défaut)"
    elif [[ "$valeur" =~ ^[0-9]+$ ]]; then
        statut="CONFORME"; detail="Port ${valeur}"
    else
        statut="A_VERIFIER"; detail="Port ${valeur} (valeur inattendue)"
    fi
    controle "SSH-03" 1 normale "$statut" "Port d'écoute SSH" \
        "$detail" "Changer de port réduit le bruit des scanners sans remplacer un vrai filtrage — à combiner avec le pare-feu"

    valeur="$(sshd_directive PermitEmptyPasswords)"
    case "$valeur" in
        no)  statut="CONFORME";     detail="PermitEmptyPasswords no" ;;
        "")  statut="A_VERIFIER";   detail="directive absente (défaut sshd : no)" ;;
        *)   statut="NON_CONFORME"; detail="PermitEmptyPasswords ${valeur}" ;;
    esac
    controle "SSH-04" 1 elevee "$statut" "Mots de passe vides en SSH" \
        "$detail" "Définir « PermitEmptyPasswords no »"

    valeur="$(sshd_directive MaxAuthTries)"
    if [[ ! "$valeur" =~ ^[0-9]+$ ]]; then
        statut="A_VERIFIER"; detail="directive absente ou illisible (défaut sshd : 6)"
    elif (( valeur <= 4 )); then
        statut="CONFORME"; detail="MaxAuthTries ${valeur}"
    else
        statut="NON_CONFORME"; detail="MaxAuthTries ${valeur} (au-delà de 4)"
    fi
    controle "SSH-05" 1 normale "$statut" "Tentatives d'authentification SSH" \
        "$detail" "Définir « MaxAuthTries 4 » pour limiter les essais par connexion"

    valeur="$(sshd_directive LoginGraceTime)"
    if [[ ! "$valeur" =~ ^[0-9]+$ ]]; then
        statut="A_VERIFIER"; detail="directive absente (défaut sshd : 120 s)"
    elif (( valeur <= 60 )); then
        statut="CONFORME"; detail="LoginGraceTime ${valeur} s"
    else
        statut="NON_CONFORME"; detail="LoginGraceTime ${valeur} s (au-delà de 60 s)"
    fi
    controle "SSH-06" 1 normale "$statut" "Délai de grâce à la connexion SSH" \
        "$detail" "Définir « LoginGraceTime 60 » afin de libérer les connexions non authentifiées"

    allowance="$(sshd_directive AllowUsers)"
    [[ -n "$allowance" ]] || allowance="$(sshd_directive AllowGroups)"
    [[ -n "$allowance" ]] || allowance="$(sshd_directive DenyUsers)"
    if [[ -n "$allowance" ]]; then
        statut="CONFORME"; detail="restriction déclarée : ${allowance}"
    else
        statut="A_VERIFIER"; detail="aucune directive AllowUsers, AllowGroups ou DenyUsers"
    fi
    controle "SSH-07" 2 normale "$statut" "Restriction des comptes autorisés en SSH" \
        "$detail" "Restreindre l'accès avec « AllowGroups ssh-users » plutôt que de laisser tout compte du système s'authentifier"

    valeur="$(sshd_directive X11Forwarding)"
    case "$valeur" in
        no)  statut="CONFORME";     detail="X11Forwarding no" ;;
        "")  statut="A_VERIFIER";   detail="directive absente (défaut sshd : no sur Debian)" ;;
        *)   statut="NON_CONFORME"; detail="X11Forwarding ${valeur}" ;;
    esac
    controle "SSH-08" 2 normale "$statut" "Transfert X11 SSH" \
        "$detail" "Définir « X11Forwarding no » : un serveur d'application n'a pas besoin de relayer X11"

    permissions="$(permissions_fichier /etc/ssh/sshd_config)"
    case "$permissions" in
        "600 root:root"|"640 root:root") statut="CONFORME"; detail="/etc/ssh/sshd_config : ${permissions}" ;;
        "") statut="A_VERIFIER"; detail="permissions illisibles" ;;
        *)  statut="NON_CONFORME"; detail="/etc/ssh/sshd_config : ${permissions} (attendu 600 root:root)" ;;
    esac
    controle "SSH-09" 1 normale "$statut" "Permissions de la configuration SSH" \
        "$detail" "Restreindre le fichier : chmod 600 /etc/ssh/sshd_config"
fi

# -----------------------------------------------------------------------------
# 2. Comptes et authentification
# -----------------------------------------------------------------------------
log_step "Comptes"
uid0="$(awk -F: '$3 == 0 { printf "%s%s", sep, $1; sep = ", " }' /etc/passwd 2>/dev/null || true)"
if [[ "$uid0" == "root" ]]; then
    statut="CONFORME"; detail="seul root possède l'UID 0"
else
    statut="NON_CONFORME"; detail="comptes avec UID 0 : ${uid0:-aucun}"
fi
controle "COMPTES-01" 1 elevee "$statut" "Unicité du compte root (UID 0)" \
    "$detail" "Retirer l'UID 0 de tout compte autre que root : c'est un second superutilisateur invisible"

if (( EUID == 0 )) && [[ -r /etc/shadow ]]; then
    sans_mot_de_passe="$(awk -F: '$2 == "" { printf "%s%s", sep, $1; sep = ", " }' /etc/shadow 2>/dev/null || true)"
    if [[ -z "$sans_mot_de_passe" ]]; then
        statut="CONFORME"; detail="aucun compte avec un mot de passe vide dans /etc/shadow"
    else
        statut="NON_CONFORME"; detail="comptes sans mot de passe : ${sans_mot_de_passe}"
    fi
    controle "COMPTES-02" 1 elevee "$statut" "Comptes sans mot de passe" \
        "$detail" "Verrouiller immédiatement : passwd -l <compte>"
else
    controle "COMPTES-02" 1 elevee "A_VERIFIER" "Comptes sans mot de passe" \
        "/etc/shadow illisible (audit lancé sans les droits root)" \
        "Relancer l'audit en root pour contrôler le second champ de /etc/shadow"
fi

comptes_systeme="$(awk -F: '
    $3 < 1000 && $3 != 0 && $7 ~ /(bash|sh|zsh|ksh|csh|tcsh|fish)$/ {
        printf "%s%s(%s)", sep, $1, $3; sep = ", "
    }' /etc/passwd 2>/dev/null || true)"
if [[ -z "$comptes_systeme" ]]; then
    statut="CONFORME"; detail="aucun compte de service doté d'un shell de connexion"
else
    statut="NON_CONFORME"; detail="comptes système avec shell : ${comptes_systeme}"
fi
controle "COMPTES-03" 1 normale "$statut" "Comptes de service avec shell de connexion" \
    "$detail" "Remplacer leur shell par /usr/sbin/nologin : usermod -s /usr/sbin/nologin <compte>"

if (( EUID == 0 )) && [[ -r /etc/shadow ]]; then
    verrouilles="$(awk -F: '
        NR == FNR { shell[$1] = $7; next }
        $1 in shell && shell[$1] ~ /(bash|sh|zsh|ksh|csh|tcsh|fish)$/ && $2 ~ /^[!*]/ {
            printf "%s%s", sep, $1; sep = ", "
        }' /etc/passwd /etc/shadow 2>/dev/null || true)"
    if [[ -z "$verrouilles" ]]; then
        statut="CONFORME"; detail="aucun compte de connexion verrouillé et inutilisé"
    else
        statut="A_VERIFIER"; detail="comptes avec shell mais mot de passe verrouillé : ${verrouilles}"
    fi
else
    statut="A_VERIFIER"; detail="/etc/shadow illisible (audit lancé sans les droits root)"
fi
controle "COMPTES-04" 1 normale "$statut" "Comptes de connexion inutilisés" \
    "$detail" "Supprimer les comptes sans propriétaire identifié, ou confirmer leur usage (une clé SSH reste utilisable sur un compte dont le mot de passe est verrouillé)"

champs_vides="$(awk -F: '
    $1 == "" || $3 == "" || $5 == "" || $6 == "" || $7 == "" {
        printf "%s%s", sep, ($1 == "" ? "?" : $1); sep = ", "
    }' /etc/passwd 2>/dev/null || true)"
if [[ -z "$champs_vides" ]]; then
    statut="CONFORME"; detail="tous les comptes de /etc/passwd ont leurs champs renseignés"
else
    statut="NON_CONFORME"; detail="lignes incomplètes dans /etc/passwd : ${champs_vides}"
fi
controle "COMPTES-05" 2 normale "$statut" "Intégrité des comptes" \
    "$detail" "Corriger les entrées incomplètes : elles peuvent avoir été insérées à la main ou par un outil tiers"

# -----------------------------------------------------------------------------
# 3. Politique de mot de passe
# -----------------------------------------------------------------------------
log_step "Politique de mot de passe"
valeur_duree="$(login_defs PASS_MAX_DAYS)"
if [[ ! "$valeur_duree" =~ ^[0-9]+$ ]]; then
    statut="A_VERIFIER"; detail="PASS_MAX_DAYS absent de /etc/login.defs"
elif (( valeur_duree <= 365 )); then
    statut="CONFORME"; detail="PASS_MAX_DAYS ${valeur_duree}"
else
    statut="NON_CONFORME"; detail="PASS_MAX_DAYS ${valeur_duree} (au-delà de 365 jours)"
fi
controle "PASS-01" 1 normale "$statut" "Durée de validité des mots de passe" \
    "$detail" "Définir « PASS_MAX_DAYS 365 » dans /etc/login.defs et appliquer avec « chage -M 365 <compte> »"

age_minimal="$(login_defs PASS_MIN_DAYS)"
if [[ ! "$age_minimal" =~ ^[0-9]+$ ]]; then
    statut="A_VERIFIER"; detail="PASS_MIN_DAYS absent de /etc/login.defs"
elif (( age_minimal >= 1 )); then
    statut="CONFORME"; detail="PASS_MIN_DAYS ${age_minimal}"
else
    statut="NON_CONFORME"; detail="PASS_MIN_DAYS ${age_minimal} (le mot de passe peut être changé immédiatement)"
fi
controle "PASS-02" 2 normale "$statut" "Âge minimal avant changement de mot de passe" \
    "$detail" "Définir « PASS_MIN_DAYS 1 » pour empêcher un utilisateur de contourner l'historique"

avertissement="$(login_defs PASS_WARN_AGE)"
if [[ ! "$avertissement" =~ ^[0-9]+$ ]]; then
    statut="A_VERIFIER"; detail="PASS_WARN_AGE absent de /etc/login.defs"
elif (( avertissement >= 7 )); then
    statut="CONFORME"; detail="PASS_WARN_AGE ${avertissement} jours"
else
    statut="NON_CONFORME"; detail="PASS_WARN_AGE ${avertissement} jours (moins de 7)"
fi
controle "PASS-03" 1 normale "$statut" "Préavis d'expiration du mot de passe" \
    "$detail" "Définir « PASS_WARN_AGE 7 » : l'utilisateur doit être prévenu avant l'expiration"

if pam_actif pam_pwquality /etc/pam.d/common-password; then
    longueur_min="$(awk -F'[=[:space:]]+' '$1 == "minlen" { print $2; exit }' /etc/security/pwquality.conf 2>/dev/null || true)"
    if [[ "$longueur_min" =~ ^[0-9]+$ ]] && (( longueur_min >= 12 )); then
        statut="CONFORME"; detail="pam_pwquality actif, minlen = ${longueur_min}"
    elif [[ -z "$longueur_min" ]]; then
        statut="A_VERIFIER"; detail="pam_pwquality actif mais minlen non défini dans /etc/security/pwquality.conf"
    else
        statut="NON_CONFORME"; detail="pam_pwquality actif, minlen = ${longueur_min} (moins de 12)"
    fi
else
    statut="NON_CONFORME"; detail="pam_pwquality (ou pam_cracklib) n'est pas activé dans /etc/pam.d/common-password"
fi
controle "PASS-04" 1 normale "$statut" "Complexité et longueur minimale des mots de passe" \
    "$detail" "Activer pam_pwquality (paquet libpam-pwquality) et fixer « minlen = 14 » dans /etc/security/pwquality.conf"

if pam_actif pam_faillock /etc/pam.d/common-auth /etc/pam.d/common-account \
   || pam_actif pam_tally2 /etc/pam.d/common-auth /etc/pam.d/common-account; then
    statut="CONFORME"; detail="verrouillage de compte après échecs configuré (pam_faillock ou pam_tally2)"
else
    statut="NON_CONFORME"; detail="aucun module de verrouillage après échecs (pam_faillock) activé"
fi
controle "PASS-05" 1 normale "$statut" "Verrouillage après échecs d'authentification" \
    "$detail" "Activer pam_faillock : deny=5, unlock_time=900, dans /etc/security/faillock.conf"

methode_chiffrement="$(login_defs ENCRYPT_METHOD)"
case "$methode_chiffrement" in
    YESCRYPT|SHA512) statut="CONFORME"; detail="ENCRYPT_METHOD ${methode_chiffrement}" ;;
    "")              statut="A_VERIFIER"; detail="ENCRYPT_METHOD absent de /etc/login.defs" ;;
    *)               statut="NON_CONFORME"; detail="ENCRYPT_METHOD ${methode_chiffrement}" ;;
esac
controle "PASS-06" 1 normale "$statut" "Algorithme de chiffrement des mots de passe" \
    "$detail" "Définir « ENCRYPT_METHOD YESCRYPT » (ou SHA512) dans /etc/login.defs"

umask_defaut="$(login_defs UMASK)"
if [[ ! "$umask_defaut" =~ ^[0-7]{3,4}$ ]]; then
    statut="A_VERIFIER"; detail="UMASK absent de /etc/login.defs (valeur par défaut : 022)"
elif (( 8#${umask_defaut} >= 8#027 )); then
    statut="CONFORME"; detail="UMASK ${umask_defaut}"
else
    statut="NON_CONFORME"; detail="UMASK ${umask_defaut} (trop permissif)"
fi
controle "PASS-07" 1 normale "$statut" "Masque de création des fichiers" \
    "$detail" "Définir « UMASK 027 » dans /etc/login.defs : les nouveaux fichiers ne doivent pas être lisibles par tous"

# -----------------------------------------------------------------------------
# 4. Sudo
# -----------------------------------------------------------------------------
log_step "Sudo"
if [[ -r /etc/sudoers ]] || [[ -d /etc/sudoers.d ]]; then
    nopasswd="$(lire_cmd grep -rhE '^[[:space:]]*[^#[:space:]].*NOPASSWD' /etc/sudoers /etc/sudoers.d)"
    if [[ -z "$nopasswd" ]]; then
        statut="CONFORME"; detail="aucune entrée NOPASSWD dans /etc/sudoers ni /etc/sudoers.d"
    else
        nombre_nopasswd="$(printf '%s\n' "$nopasswd" | wc -l | tr -d ' ')"
        apercu="$(printf '%s\n' "$nopasswd" | head -n 3 | tr '\n' ';')"
        statut="NON_CONFORME"; detail="${nombre_nopasswd} entrée(s) sans mot de passe : ${apercu}"
    fi
else
    statut="A_VERIFIER"; detail="ni /etc/sudoers ni /etc/sudoers.d ne sont lisibles"
fi
controle "SUDO-01" 1 elevee "$statut" "Exécution sudo sans mot de passe" \
    "$detail" "Exiger le mot de passe : toute session laissée ouverte devient équivalente à un accès root"

sudoers_mauvais=""
for fichier in /etc/sudoers /etc/sudoers.d /etc/sudoers.d/*; do
    [[ -e "$fichier" ]] || continue
    permissions="$(permissions_fichier "$fichier")"
    case "$permissions" in
        "440 root:root"|"400 root:root"|"750 root:root"|"700 root:root"|"500 root:root"|"550 root:root") ;;
        "") sudoers_mauvais="${sudoers_mauvais} ${fichier} (illisible)" ;;
        *)  sudoers_mauvais="${sudoers_mauvais} ${fichier} (${permissions})" ;;
    esac
done
if [[ -z "$sudoers_mauvais" ]]; then
    statut="CONFORME"; detail="permissions conformes (0440 root:root pour les fichiers, 0750 pour le répertoire)"
else
    statut="NON_CONFORME"; detail="permissions à corriger :${sudoers_mauvais}"
fi
controle "SUDO-02" 1 elevee "$statut" "Permissions de la configuration sudo" \
    "$detail" "Corriger avec « chmod 440 /etc/sudoers /etc/sudoers.d/* » et « chown root:root » — un fichier sudoers modifiable par un tiers vaut un accès root"

# -----------------------------------------------------------------------------
# 5. Pare-feu
# -----------------------------------------------------------------------------
log_step "Pare-feu"
parefeu_actif="0"; parefeu_nom="aucun"; politique_defaut=""
if command -v ufw >/dev/null 2>&1; then
    # « status verbose » est la seule forme qui affiche la politique par défaut
    etat_ufw="$(lire_cmd ufw status verbose)"
    if [[ "$etat_ufw" == *"Status: active"* ]]; then
        parefeu_actif="1"; parefeu_nom="ufw"
        if [[ "$etat_ufw" == *"deny (incoming)"* ]]; then
            politique_defaut="deny (entrant)"
        fi
    fi
fi
if ! (( parefeu_actif )) && command -v nft >/dev/null 2>&1; then
    regles_nft="$(lire_cmd nft list ruleset)"
    if [[ -n "$regles_nft" ]]; then
        parefeu_actif="1"; parefeu_nom="nftables"
        if [[ "$regles_nft" == *"policy drop"* ]]; then
            politique_defaut="drop"
        fi
    fi
fi
if ! (( parefeu_actif )) && command -v firewall-cmd >/dev/null 2>&1; then
    etat_firewalld="$(lire_cmd firewall-cmd --state)"
    if [[ "$etat_firewalld" == "running" ]]; then
        parefeu_actif="1"; parefeu_nom="firewalld"
        politique_defaut="$(lire_cmd firewall-cmd --get-default-zone)"
    fi
fi
if ! (( parefeu_actif )) && command -v iptables >/dev/null 2>&1; then
    regles_iptables="$(lire_cmd iptables -S)"
    if [[ "$regles_iptables" == *"-P INPUT DROP"* || "$regles_iptables" == *"-P INPUT REJECT"* ]]; then
        parefeu_actif="1"; parefeu_nom="iptables"
        politique_defaut="drop"
    fi
fi

if (( parefeu_actif )); then
    statut="CONFORME"; detail="pare-feu actif : ${parefeu_nom}"
else
    statut="NON_CONFORME"; detail="aucun pare-feu actif détecté (ufw, nftables, firewalld, iptables)"
fi
controle "FW-01" 1 elevee "$statut" "Pare-feu actif" \
    "$detail" "Activer un pare-feu et n'ouvrir que les ports nécessaires : « ufw default deny incoming » puis « ufw allow <service> »"

if ! (( parefeu_actif )); then
    statut="A_VERIFIER"; detail="politique par défaut non vérifiable sans pare-feu actif"
elif [[ -z "$politique_defaut" ]]; then
    statut="A_VERIFIER"; detail="pare-feu ${parefeu_nom} actif mais politique entrante par défaut non identifiable"
else
    statut="CONFORME"; detail="politique entrante par défaut : ${politique_defaut}"
fi
controle "FW-02" 1 normale "$statut" "Politique par défaut du pare-feu" \
    "$detail" "Refuser par défaut en entrée (« deny »/« drop ») et autoriser explicitement chaque service"

# -----------------------------------------------------------------------------
# 6. Fail2ban
# -----------------------------------------------------------------------------
log_step "Fail2ban"
if command -v fail2ban-client >/dev/null 2>&1; then
    statut="CONFORME"; detail="fail2ban-client présent"
else
    statut="NON_CONFORME"; detail="fail2ban n'est pas installé"
fi
controle "F2B-01" 1 normale "$statut" "Installation de fail2ban" \
    "$detail" "Installer fail2ban pour bloquer automatiquement les tentatives d'authentification répétées"

etat_fail2ban=""
if command -v systemctl >/dev/null 2>&1; then
    etat_fail2ban="$(lire_cmd systemctl is-active fail2ban)"
fi
if [[ "$etat_fail2ban" == "active" ]]; then
    statut="CONFORME"; detail="service fail2ban actif"
else
    statut="NON_CONFORME"; detail="service fail2ban inactif (état : ${etat_fail2ban:-inconnu})"
fi
controle "F2B-02" 1 normale "$statut" "Service fail2ban actif" \
    "$detail" "Activer le service : systemctl enable --now fail2ban"

if [[ "$etat_fail2ban" == "active" ]]; then
    jails="$(lire_cmd fail2ban-client status)"
    jails="${jails##*Jail list:}"
    jails="$(printf '%s' "$jails" | tr -d ',' | awk '{$1=$1; print}')"
    if [[ -n "$jails" ]]; then
        statut="CONFORME"; detail="jails actives : ${jails}"
    else
        statut="NON_CONFORME"; detail="aucune jail active"
    fi
else
    statut="A_VERIFIER"; detail="jails non vérifiables, le service fail2ban n'est pas actif"
fi
controle "F2B-03" 2 normale "$statut" "Jails fail2ban configurées" \
    "$detail" "Activer au minimum une jail sshd dans /etc/fail2ban/jail.local"

# -----------------------------------------------------------------------------
# 7. Mises à jour automatiques
# -----------------------------------------------------------------------------
log_step "Mises à jour"
paquet_unattended="0"
if command -v dpkg-query >/dev/null 2>&1; then
    if dpkg-query -s unattended-upgrades >/dev/null 2>&1; then
        paquet_unattended="1"
    fi
elif command -v rpm >/dev/null 2>&1; then
    if rpm -q dnf-automatic >/dev/null 2>&1; then
        paquet_unattended="1"
    fi
fi

if (( paquet_unattended )); then
    statut="CONFORME"; detail="unattended-upgrades est installé"
else
    statut="NON_CONFORME"; detail="unattended-upgrades (ou dnf-automatic) n'est pas installé"
fi
controle "MAJ-01" 1 normale "$statut" "Mises à jour de sécurité automatiques" \
    "$detail" "Installer unattended-upgrades : les correctifs de sécurité arrivent alors sans intervention"

periodique="$(lire_cmd grep -h '^APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades)"
if [[ "$periodique" == *'"1"'* ]]; then
    statut="CONFORME"; detail="mise à jour automatique activée (${periodique})"
else
    statut="NON_CONFORME"; detail="APT::Periodic::Unattended-Upgrade n'est pas à 1"
fi
controle "MAJ-02" 1 normale "$statut" "Activation du planificateur de mises à jour" \
    "$detail" "Définir « APT::Periodic::Unattended-Upgrade \"1\"; » dans /etc/apt/apt.conf.d/20auto-upgrades"

if [[ -r /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    origines="$(lire_cmd grep -c 'security' /etc/apt/apt.conf.d/50unattended-upgrades)"
    if [[ "$origines" =~ ^[0-9]+$ ]] && (( origines > 0 )); then
        statut="CONFORME"; detail="dépôt de sécurité déclaré dans 50unattended-upgrades"
    else
        statut="NON_CONFORME"; detail="aucune origine de sécurité déclarée dans 50unattended-upgrades"
    fi
else
    statut="A_VERIFIER"; detail="/etc/apt/apt.conf.d/50unattended-upgrades absent"
fi
controle "MAJ-03" 2 normale "$statut" "Périmètre des mises à jour automatiques" \
    "$detail" "Vérifier que les origines de sécurité (security) sont décommentées dans /etc/apt/apt.conf.d/50unattended-upgrades"

# -----------------------------------------------------------------------------
# 8. Binaires SUID et SGID
# -----------------------------------------------------------------------------
log_step "Binaires SUID et SGID"
REPERTOIRES_BINAIRES=(/bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local /opt)

collecter_permissions_speciales() {
    local perm="$1"
    find "${REPERTOIRES_BINAIRES[@]}" -xdev -type f -perm "$perm" 2>/dev/null || true
}

suid_inconnus=""; nb_suid=0; nb_suid_inconnus=0
while IFS= read -r fichier; do
    [[ -n "$fichier" ]] || continue
    (( nb_suid++ )) || true
    if ! contient "${fichier##*/}" "${LISTE_BLANCHE_SUID[@]}"; then
        (( nb_suid_inconnus++ )) || true
        if (( nb_suid_inconnus <= 6 )); then
            suid_inconnus="${suid_inconnus}${suid_inconnus:+, }${fichier}"
        fi
    fi
done < <(collecter_permissions_speciales -4000)
if (( nb_suid_inconnus > 6 )); then
    suid_inconnus="${suid_inconnus}, … (+$(( nb_suid_inconnus - 6 )) autres)"
fi
if (( nb_suid_inconnus == 0 )); then
    statut="CONFORME"; detail="${nb_suid} binaire(s) SUID, tous dans la liste blanche"
else
    statut="NON_CONFORME"; detail="${nb_suid_inconnus} binaire(s) SUID hors liste blanche : ${suid_inconnus}"
fi
controle "SUID-01" 1 elevee "$statut" "Binaires SUID hors liste blanche" \
    "$detail" "Vérifier l'origine de chaque binaire SUID ; retirer le bit avec « chmod u-s <fichier> » s'il est inutile — un SUID détourné donne root"

sgid_inconnus=""; nb_sgid=0; nb_sgid_inconnus=0
while IFS= read -r fichier; do
    [[ -n "$fichier" ]] || continue
    (( nb_sgid++ )) || true
    if ! contient "${fichier##*/}" "${LISTE_BLANCHE_SGID[@]}"; then
        (( nb_sgid_inconnus++ )) || true
        if (( nb_sgid_inconnus <= 6 )); then
            sgid_inconnus="${sgid_inconnus}${sgid_inconnus:+, }${fichier}"
        fi
    fi
done < <(collecter_permissions_speciales -2000)
if (( nb_sgid_inconnus > 6 )); then
    sgid_inconnus="${sgid_inconnus}, … (+$(( nb_sgid_inconnus - 6 )) autres)"
fi
if (( nb_sgid_inconnus == 0 )); then
    statut="CONFORME"; detail="${nb_sgid} binaire(s) SGID, tous dans la liste blanche"
else
    statut="NON_CONFORME"; detail="${nb_sgid_inconnus} binaire(s) SGID hors liste blanche : ${sgid_inconnus}"
fi
controle "SUID-02" 1 normale "$statut" "Binaires SGID hors liste blanche" \
    "$detail" "Contrôler les binaires SGID : ils héritent du groupe du fichier, souvent un groupe privilégié"

# -----------------------------------------------------------------------------
# 9. Permissions critiques
# -----------------------------------------------------------------------------
log_step "Permissions"
modifiables="$(lire_cmd find /etc -xdev -type f -perm -0002)"
if [[ -z "$modifiables" ]]; then
    statut="CONFORME"; detail="aucun fichier de /etc modifiable par tous"
else
    nombre_modifiables="$(printf '%s\n' "$modifiables" | wc -l | tr -d ' ')"
    apercu="$(printf '%s\n' "$modifiables" | head -n 5 | tr '\n' ' ')"
    statut="NON_CONFORME"; detail="${nombre_modifiables} fichier(s) modifiable(s) par tous : ${apercu}"
fi
controle "PERM-01" 1 elevee "$statut" "Fichiers de /etc modifiables par tous" \
    "$detail" "Retirer le droit d'écriture au reste du monde (chmod o-w) : un fichier de configuration inscriptible par tous est une porte d'entrée"

mauvais_passwd=""
for fichier in /etc/passwd /etc/group; do
    permissions="$(permissions_fichier "$fichier")"
    case "$permissions" in
        "644 root:root") ;;
        "") mauvais_passwd="${mauvais_passwd} ${fichier} (illisible)" ;;
        *)  mauvais_passwd="${mauvais_passwd} ${fichier} (${permissions})" ;;
    esac
done
if [[ -z "$mauvais_passwd" ]]; then
    statut="CONFORME"; detail="/etc/passwd et /etc/group : 644 root:root"
else
    statut="NON_CONFORME"; detail="permissions inattendues : ${mauvais_passwd}"
fi
controle "PERM-02" 1 elevee "$statut" "Permissions de /etc/passwd et /etc/group" \
    "$detail" "Rétablir « chmod 644 /etc/passwd /etc/group » et « chown root:root »"

if (( EUID == 0 )); then
    mauvais_shadow=""
    for fichier in /etc/shadow /etc/gshadow; do
        permissions="$(permissions_fichier "$fichier")"
        case "$permissions" in
            "640 root:shadow"|"600 root:root"|"400 root:root"|"000 root:root") ;;
            *) mauvais_shadow="${mauvais_shadow} ${fichier} (${permissions:-absent})" ;;
        esac
    done
    if [[ -z "$mauvais_shadow" ]]; then
        statut="CONFORME"; detail="/etc/shadow et /etc/gshadow : 640 root:shadow"
    else
        statut="NON_CONFORME"; detail="permissions inattendues :${mauvais_shadow}"
    fi
else
    statut="A_VERIFIER"; detail="audit lancé sans les droits root, permissions de /etc/shadow non lues"
fi
controle "PERM-03" 1 elevee "$statut" "Permissions de /etc/shadow et /etc/gshadow" \
    "$detail" "Rétablir « chmod 640 /etc/shadow /etc/gshadow » et « chown root:shadow » — ces fichiers portent tous les condensats de mots de passe"

cron_modifiables=""
for chemin in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    [[ -e "$chemin" ]] || continue
    permissions="$(stat -c '%a' "$chemin" 2>/dev/null || true)"
    if [[ "$permissions" =~ ^[0-7]+$ ]] && (( 8#${permissions} % 10 != 0 )); then
        cron_modifiables="${cron_modifiables} ${chemin} (${permissions})"
    fi
done
if [[ -z "$cron_modifiables" ]]; then
    statut="CONFORME"; detail="planification (cron) accessible en écriture au seul propriétaire"
else
    statut="NON_CONFORME"; detail="chemins modifiables par tous :${cron_modifiables}"
fi
controle "PERM-04" 2 normale "$statut" "Permissions des tâches planifiées" \
    "$detail" "Restreindre /etc/cron* et /var/spool/cron : une tâche déposée par un tiers s'exécute au nom prévu par le système"

# -----------------------------------------------------------------------------
# 10. Réseau exposé
# -----------------------------------------------------------------------------
log_step "Services exposés"
PORTS_EN_ECOUTE=""
if command -v ss >/dev/null 2>&1; then
    PORTS_EN_ECOUTE="$(lire_cmd ss -H -tuln | awk '{ print $1 " " $5 }')"
    exposes="$(printf '%s\n' "$PORTS_EN_ECOUTE" | awk '
        $2 ~ /^(\*|0\.0\.0\.0|\[::\]|\*\.)/ { print $2 "/" $1 }' | sort -u | awk '
        { printf "%s%s", sep, $0; sep = ", " }')"
    nb_exposes="$(printf '%s\n' "$PORTS_EN_ECOUTE" | awk '
        $2 ~ /^(\*|0\.0\.0\.0|\[::\]|\*\.)/' | wc -l | tr -d ' ')"
    if [[ -z "$exposes" ]]; then
        statut="CONFORME"; detail="aucun service en écoute sur toutes les interfaces"
    else
        statut="A_VERIFIER"
        detail="${nb_exposes} écoute(s) sur toutes les interfaces : $(tronquer_liste "$exposes" 12)"
    fi
    controle "ECR-01" 1 normale "$statut" "Services en écoute sur toutes les interfaces" \
        "$detail" "Chaque écoute sur 0.0.0.0 doit être justifiée ; sinon, restreindre à l'adresse utile (127.0.0.1, réseau interne) ou filtrer avec le pare-feu"

    herites="$(printf '%s\n' "$PORTS_EN_ECOUTE" | awk '
        { n = split($2, parts, ":"); port = parts[n]
          if (port == 21 || port == 23 || port == 69 || port == 512 || port == 513 || port == 514)
              print $2 "/" $1 }' | sort -u | awk '{ printf "%s%s", sep, $0; sep = ", " }')"
    if [[ -z "$herites" ]]; then
        statut="CONFORME"; detail="aucun service hérité en écoute (ftp, telnet, tftp, rsh)"
    else
        statut="NON_CONFORME"; detail="protocoles non chiffrés en écoute : ${herites}"
    fi
    controle "ECR-02" 1 normale "$statut" "Protocoles réseau hérités" \
        "$detail" "Remplacer ftp/telnet/rsh par SSH ou SFTP : ces protocoles transmettent les identifiants en clair"
else
    controle "ECR-01" 1 normale "A_VERIFIER" "Services en écoute sur toutes les interfaces" \
        "commande ss absente : impossible de lister les ports en écoute" \
        "Installer iproute2 pour inventorier les services exposés"
fi

# -----------------------------------------------------------------------------
# 11. Paramètres noyau
# -----------------------------------------------------------------------------
log_step "Paramètres noyau"
controle_sysctl "SYSCTL-01" 1 normale "kernel.randomize_va_space" "2" \
    "Randomisation de l'espace d'adressage (ASLR)" \
    "Définir « kernel.randomize_va_space = 2 » dans /etc/sysctl.d/99-durcissement.conf"

controle_sysctl "SYSCTL-02" 1 normale "net.ipv4.ip_forward" "0" \
    "Routage IPv4 désactivé" \
    "Désactiver le routage sauf si la machine est un routeur : « net.ipv4.ip_forward = 0 »"

controle_sysctl "SYSCTL-03" 1 normale "net.ipv4.conf.all.accept_redirects" "0" \
    "Redirections ICMP ignorées" \
    "Refuser les redirections ICMP : « net.ipv4.conf.all.accept_redirects = 0 » et idem pour default"

controle_sysctl "SYSCTL-04" 1 normale "net.ipv4.conf.all.accept_source_route" "0" \
    "Routage par la source refusé" \
    "Refuser le source routing : « net.ipv4.conf.all.accept_source_route = 0 »"

controle_sysctl "SYSCTL-05" 1 normale "net.ipv4.conf.all.rp_filter" "1|2" \
    "Vérification du chemin retour (anti-usurpation)" \
    "Activer le filtrage inverse : « net.ipv4.conf.all.rp_filter = 1 »"

controle_sysctl "SYSCTL-06" 1 normale "net.ipv4.conf.all.log_martians" "1" \
    "Journalisation des paquets impossibles" \
    "Journaliser les paquets à l'adresse source invalide : « net.ipv4.conf.all.log_martians = 1 »"

controle_sysctl "SYSCTL-07" 1 normale "net.ipv4.icmp_echo_ignore_broadcasts" "1" \
    "ICMP de diffusion ignoré (anti-amplification)" \
    "Ignorer les requêtes ICMP de diffusion : « net.ipv4.icmp_echo_ignore_broadcasts = 1 »"

controle_sysctl "SYSCTL-08" 2 normale "kernel.dmesg_restrict" "1" \
    "Accès au journal noyau restreint" \
    "Définir « kernel.dmesg_restrict = 1 » : la mémoire du noyau peut fuiter des adresses exploitables"

controle_sysctl "SYSCTL-09" 2 normale "kernel.kptr_restrict" "1|2" \
    "Adresses du noyau masquées" \
    "Définir « kernel.kptr_restrict = 2 » pour masquer les adresses dans /proc"

controle_sysctl "SYSCTL-10" 2 normale "fs.suid_dumpable" "0" \
    "Cœurs mémoire des programmes SUID désactivés" \
    "Définir « fs.suid_dumpable = 0 » : un vidage de mémoire de programme privilégié expose des données sensibles"

# -----------------------------------------------------------------------------
# 12. Synchronisation horaire
# -----------------------------------------------------------------------------
log_step "Synchronisation horaire"
synchro=""
if command -v timedatectl >/dev/null 2>&1; then
    synchro="$(lire_cmd timedatectl show -p NTPSynchronized --value)"
fi
if [[ "$synchro" == "yes" ]]; then
    statut="CONFORME"; detail="horloge synchronisée (timedatectl)"
else
    statut="NON_CONFORME"; detail="horloge non synchronisée (état : ${synchro:-inconnu})"
fi
controle "NTP-01" 1 normale "$statut" "Horloge synchronisée" \
    "$detail" "Activer un client NTP (systemd-timesyncd ou chrony) : des horodatages faux rendent les journaux et les certificats inexploitables"

service_temps="aucun"
for service in systemd-timesyncd chronyd ntp ntpsec; do
    etat_service=""
    if command -v systemctl >/dev/null 2>&1; then
        etat_service="$(lire_cmd systemctl is-enabled "$service")"
    fi
    if [[ "$etat_service" == "enabled" ]]; then
        service_temps="$service"
        break
    fi
done
if [[ "$service_temps" == "aucun" ]]; then
    statut="NON_CONFORME"; detail="aucun service de temps activé au démarrage"
else
    statut="CONFORME"; detail="service de temps activé : ${service_temps}"
fi
controle "NTP-02" 2 normale "$statut" "Service de temps persistant" \
    "$detail" "Activer le service au démarrage : « systemctl enable --now systemd-timesyncd »"

# -----------------------------------------------------------------------------
# 13. Audit système (auditd)
# -----------------------------------------------------------------------------
log_step "auditd"
auditd_present="0"
if command -v auditctl >/dev/null 2>&1 || [[ -d /etc/audit ]]; then
    auditd_present="1"
fi
if (( auditd_present )); then
    statut="CONFORME"; detail="auditd est installé"
else
    statut="NON_CONFORME"; detail="auditd n'est pas installé"
fi
controle "AUDIT-01" 1 normale "$statut" "Installation d'auditd" \
    "$detail" "Installer auditd pour conserver une trace exploitable des actions privilégiées"

etat_auditd=""
if command -v systemctl >/dev/null 2>&1; then
    etat_auditd="$(lire_cmd systemctl is-active auditd)"
fi
if [[ "$etat_auditd" == "active" ]]; then
    statut="CONFORME"; detail="service auditd actif"
else
    statut="NON_CONFORME"; detail="service auditd inactif (état : ${etat_auditd:-inconnu})"
fi
controle "AUDIT-02" 2 normale "$statut" "Service auditd actif" \
    "$detail" "Activer le service : « systemctl enable --now auditd »"

if [[ -d /etc/audit/rules.d ]]; then
    nb_regles_audit="$(lire_cmd grep -c '^-' /etc/audit/rules.d/*.rules | awk -F: '{ s += $2 } END { print s+0 }')"
    if [[ "$nb_regles_audit" =~ ^[0-9]+$ ]] && (( nb_regles_audit > 0 )); then
        statut="CONFORME"; detail="${nb_regles_audit} règle(s) d'audit déclarée(s)"
    else
        statut="NON_CONFORME"; detail="aucune règle d'audit déclarée dans /etc/audit/rules.d"
    fi
else
    statut="NON_CONFORME"; detail="/etc/audit/rules.d est absent"
fi
controle "AUDIT-03" 2 normale "$statut" "Règles d'audit définies" \
    "$detail" "Décrire au minimum l'identité (identity), les modifications de comptes et d'horodatage (time-change) dans /etc/audit/rules.d/"

# -----------------------------------------------------------------------------
# 14. Options de montage
# -----------------------------------------------------------------------------
log_step "Options de montage"
for point in /tmp /dev/shm; do
    identifiant="MONT-01"
    niveau="1"
    titre="Options de montage de ${point}"
    if [[ "$point" == "/dev/shm" ]]; then
        identifiant="MONT-02"
    fi
    options="$(options_montage "$point")"
    if [[ -z "$options" ]]; then
        statut="NON_CONFORME"
        detail="${point} n'est pas monté séparément (options héritées de la racine)"
    else
        manquantes=""
        for option in nodev nosuid noexec; do
            if [[ "$options" != *"${option}"* ]]; then
                manquantes="${manquantes} ${option}"
            fi
        done
        if [[ -z "$manquantes" ]]; then
            statut="CONFORME"; detail="${point} monté avec ${options}"
        else
            statut="NON_CONFORME"; detail="${point} monté avec ${options} — options manquantes :${manquantes}"
        fi
    fi
    controle "$identifiant" "$niveau" normale "$statut" "$titre" \
        "$detail" "Monter ${point} avec nodev,nosuid,noexec dans /etc/fstab : aucun binaire ne doit s'exécuter depuis un répertoire temporaire"
done

options_home="$(options_montage /home)"
if [[ -z "$options_home" ]]; then
    statut="NON_CONFORME"; detail="/home n'est pas monté séparément"
elif [[ "$options_home" == *nodev* ]]; then
    statut="CONFORME"; detail="/home monté avec ${options_home}"
else
    statut="NON_CONFORME"; detail="/home monté avec ${options_home} — option manquante : nodev"
fi
controle "MONT-03" 2 normale "$statut" "Options de montage de /home" \
    "$detail" "Ajouter nodev (et nosuid) sur /home : les répertoires utilisateurs ne doivent pas porter de fichiers de périphériques"

# -----------------------------------------------------------------------------
# 15. Accès console et bannières
# -----------------------------------------------------------------------------
log_step "Console et bannières"
if [[ ! -e /etc/securetty ]]; then
    statut="CONFORME"; detail="/etc/securetty absent : la console root est gérée par PAM et systemd"
else
    consoles="$(awk '!/^[[:space:]]*(#|$)/ { printf "%s%s", sep, $1; sep = ", " }' /etc/securetty 2>/dev/null || true)"
    if [[ -z "$consoles" ]]; then
        statut="CONFORME"; detail="/etc/securetty ne déclare aucune console"
    else
        statut="A_VERIFIER"; detail="connexion root autorisée sur les consoles : ${consoles}"
    fi
fi
controle "SEC-01" 1 normale "$statut" "Accès root à la console physique" \
    "$detail" "Vider /etc/securetty sur une machine en datacenter : personne ne se connecte au clavier, et une session console ouverte vaut un accès root"

bannieres=""
for fichier in /etc/issue /etc/issue.net; do
    [[ -r "$fichier" ]] || continue
    contenu="$(tr -d '\n\r' < "$fichier" 2>/dev/null || true)"
    if [[ "$contenu" == *'\n'* || "$contenu" == *'\r'* || "$contenu" == *'\m'* || "$contenu" == *'\s'* || "$contenu" == *'\v'* || "$contenu" == *"$DISTRIBUTION"* ]]; then
        bannieres="${bannieres} ${fichier}"
    fi
done
if [[ -z "$bannieres" ]]; then
    statut="CONFORME"; detail="/etc/issue et /etc/issue.net ne divulguent pas d'information système"
else
    statut="NON_CONFORME"; detail="information système exposée avant authentification :${bannieres}"
fi
controle "DIV-01" 2 normale "$statut" "Bannières de connexion neutres" \
    "$detail" "Ne pas divulguer la distribution ni la version du noyau : mentionner seulement une autorisation d'accès dans /etc/issue et /etc/issue.net"

if command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1; then
    statut="A_VERIFIER"; detail="un compilateur C est installé sur cet hôte"
else
    statut="CONFORME"; detail="aucun compilateur C détecté"
fi
controle "DIV-02" 2 normale "$statut" "Présence d'un compilateur" \
    "$detail" "Un compilateur sur un serveur d'exécution permet de reconstruire un outil détourné : le réserver aux machines de compilation"

# -----------------------------------------------------------------------------
# Sortie
# -----------------------------------------------------------------------------

# Échappe une valeur pour du JSON (les détails contiennent des chemins et des
# guillemets, un JSON non échappé serait invalide).
echapper_json() {
    local valeur="$1"
    valeur="${valeur//\\/\\\\}"
    valeur="${valeur//\"/\\\"}"
    valeur="${valeur//$'\n'/\\n}"
    valeur="${valeur//$'\r'/\\r}"
    valeur="${valeur//$'\t'/\\t}"
    printf '%s' "$valeur"
}

libelle_statut() {
    case "$1" in
        CONFORME)     printf 'CONFORME' ;;
        NON_CONFORME) printf 'NON CONFORME' ;;
        *)            printf 'À VÉRIFIER' ;;
    esac
}

couleur_statut() {
    case "$1" in
        CONFORME)     printf '%s' "$C_OK" ;;
        NON_CONFORME) printf '%s' "$C_ERR" ;;
        *)            printf '%s' "$C_WARN" ;;
    esac
}

resume_texte() {
    printf '\n%sRésumé : %d conforme(s), %d non conforme(s), %d à vérifier — %d contrôle(s) au niveau CIS %s%s\n' \
        "$C_INFO" "$NB_CONFORME" "$NB_NON_CONFORME" "$NB_A_VERIFIER" "${#CONTROLES[@]}" "$NIVEAU" "$C_RESET"
}

sortie_texte() {
    local entree id niveau criticite statut titre detail recommandation
    printf '%sAudit de durcissement — %s%s\n' "$C_INFO" "$HOTE_COURT" "$C_RESET"
    printf 'Distribution  : %s\n' "$DISTRIBUTION"
    printf 'Date          : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf 'Niveau CIS    : %s\n' "$NIVEAU"
    printf 'Contrôles     : %s exécuté(s)\n' "${#CONTROLES[@]}"
    for entree in "${CONTROLES[@]}"; do
        IFS=$'\t' read -r id niveau criticite statut titre detail recommandation <<< "$entree"
        if (( PROBLEMES )) && [[ "$statut" == "CONFORME" ]]; then
            continue
        fi
        printf '\n%s[%-12s]%s %-10s %s\n' \
            "$(couleur_statut "$statut")" "$(libelle_statut "$statut")" "$C_RESET" "$id" "$titre"
        printf '    %s\n' "$detail"
        if [[ "$statut" != "CONFORME" ]]; then
            printf '    %s-> %s%s\n' "$C_DIM" "$recommandation" "$C_RESET"
        fi
    done
    resume_texte
}

sortie_json() {
    local entree id niveau criticite statut titre detail recommandation premier=1
    printf '{\n'
    printf '  "script": "audit-hardening.sh",\n'
    printf '  "version": "%s",\n' "$VERSION_SCRIPT"
    printf '  "date": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "hote": "%s",\n' "$(echapper_json "$HOTE_COURT")"
    printf '  "distribution": "%s",\n' "$(echapper_json "$DISTRIBUTION")"
    printf '  "niveau": %s,\n' "$NIVEAU"
    printf '  "resume": {"conforme": %d, "non_conforme": %d, "a_verifier": %d, "total": %d},\n' \
        "$NB_CONFORME" "$NB_NON_CONFORME" "$NB_A_VERIFIER" "${#CONTROLES[@]}"
    printf '  "controles": [\n'
    for entree in "${CONTROLES[@]}"; do
        IFS=$'\t' read -r id niveau criticite statut titre detail recommandation <<< "$entree"
        if (( PROBLEMES )) && [[ "$statut" == "CONFORME" ]]; then
            continue
        fi
        if (( premier )); then
            premier=0
        else
            printf ',\n'
        fi
        printf '    {"id": "%s", "niveau": %s, "criticite": "%s", "statut": "%s", "titre": "%s", "detail": "%s", "recommandation": "%s"}' \
            "$(echapper_json "$id")" "$niveau" "$(echapper_json "$criticite")" "$statut" \
            "$(echapper_json "$titre")" "$(echapper_json "$detail")" "$(echapper_json "$recommandation")"
    done
    printf '\n  ]\n}\n'
}

if [[ "$FORMAT" == "json" ]]; then
    sortie_json
elif (( QUIET )); then
    # En mode silencieux, seule la synthèse est rédigée : le détail reste
    # disponible via --json ou --rapport.
    printf '%s : %d conforme(s), %d non conforme(s), %d à vérifier (%d contrôle(s), niveau CIS %s)\n' \
        "$HOTE_COURT" "$NB_CONFORME" "$NB_NON_CONFORME" "$NB_A_VERIFIER" "${#CONTROLES[@]}" "$NIVEAU"
else
    sortie_texte
fi

if [[ -n "$RAPPORT" ]]; then
    if ! sortie_texte > "$RAPPORT"; then
        die "Impossible d'écrire le rapport dans ${RAPPORT}"
    fi
    log_ok "Rapport écrit dans ${RAPPORT}"
fi

log_info "Audit terminé : ${NB_CONFORME} conforme(s), ${NB_NON_CONFORME} non conforme(s), ${NB_A_VERIFIER} à vérifier"

if (( NB_CRITIQUES > 0 )); then
    fin_script "Audit terminé : écarts critiques"
    exit 2
fi
if (( NB_NON_CONFORME > 0 || NB_A_VERIFIER > 0 )); then
    fin_script "Audit terminé : écarts mineurs"
    exit 1
fi

fin_script "Audit terminé : conforme"
exit 0
