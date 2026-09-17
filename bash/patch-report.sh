#!/usr/bin/env bash
# =============================================================================
# patch-report.sh — État des correctifs d'un hôte Linux (lecture seule)
# -----------------------------------------------------------------------------
# Renseigne l'état de mise à jour d'un hôte : gestionnaire de paquets détecté,
# nombre de mises à jour disponibles, mises à jour de sécurité quand le
# gestionnaire sait les distinguer, besoin de redémarrage, fraîcheur du dernier
# passage de mises à jour et présence d'une mise à jour automatique.
#
# Pourquoi : la conformité de correctifs se vérifie hôte par hôte, à la main,
# et devient vite approximative. Un rapport lisible, un JSON exploitable par la
# supervision et des codes retour 0/1/2 suffisent à alimenter un tableau de
# bord ou une revue de sécurité.
#
# LECTURE SEULE PAR DÉFAUT : le script travaille sur les données déjà en cache
# et ne lance aucun rafraîchissement d'index (pas de « apt update »). Une
# actualisation n'a lieu qu'avec --rafraichir, qui est une opération écrivable
# et donc refusée sans les droits de root.
#
# Gestionnaires pris en charge : apt, dnf, yum, pacman, zypper.
#
# Limites connues :
#   - la distinction mise à jour simple / mise à jour de sécurité repose sur
#     l'origine du paquet (dépôt « security ») : c'est une heuristique, elle est
#     signalée comme non déterminée quand le gestionnaire ne la fournit pas ;
#   - les mises à jour de sécurité sont comptées en nombre de paquets, pas en
#     nombre d'avis de sécurité (CVE).
#
# Codes retour :
#   0  hôte à jour au regard des seuils
#   1  avertissement (retard, paquets en attente, sécurité en attente,
#      redémarrage requis, inventaire indisponible) ou erreur d'exécution
#   2  point critique (seuil doublé, ou sécurité en attente avec
#      --securite-critique) ou paramètres invalides
#
# Exemples :
#   ./patch-report.sh
#   ./patch-report.sh --hote srv-web-01 --max-retard 15 --max-paquets 10
#   ./patch-report.sh --json | jq '{mises_a_jour, retard_jours}'
#   ./patch-report.sh --securite-critique --max-paquets 0
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Les nombres doivent se formater avec un point décimal (JSON), jamais avec une
# virgule : la locale de l'opérateur ne doit pas casser la supervision.
export LC_NUMERIC=C

# --- Valeurs par défaut ------------------------------------------------------
HOTE=""
GESTIONNAIRE_FORCE=""
RAFRAICHIR=0
MAX_RETARD=30
MAX_PAQUETS=20
SECURITE_CRITIQUE=0
FORMAT="texte"

GESTIONNAIRE=""
CMD=""

NB_MAJ=0
NB_SEC=0
SEC_CONNUE="non"
ORIGINE_SEC=""
PAQUETS_OK=0                # 1 = inventaire des mises à jour exploitable
LISTE_MAJ=()
DETAIL_INVENTAIRE=""

REDEMARRAGE="non"
RAISON_REDEMARRAGE=""
NOYAU_EN_COURS=""

EPOCH_MAJ=""
SOURCE_MAJ=""
RETARD_JOURS=""
RETARD_JSON="null"
DETAIL_MAJ=""

MAJ_AUTO="non"
DETAIL_MAJ_AUTO=""

NB_OK=0
NB_WARN=0
NB_CRIT=0
RESULTATS=()

usage() {
    entete_script "État des correctifs d'un hôte Linux, en lecture seule par défaut."
    cat >&2 <<'EOF'

Usage :
  patch-report.sh [options]

Options :
      --hote <nom>            Nom affiché dans le rapport (défaut : nom de l'hôte)
      --gestionnaire <nom>    Force le gestionnaire : apt, dnf, yum, pacman, zypper
                              (défaut : détection automatique ; utile en chroot)
      --rafraichir            Actualise explicitement le cache des paquets.
                              SANS cette option, RIEN N'EST MODIFIÉ : le rapport
                              se fonde sur les données déjà en cache. Avec elle,
                              le script écrit sur le système (apt update,
                              dnf makecache, pacman -Sy, zypper refresh) et
                              exige les droits de root.
      --max-retard <jours>    Retard maximal du dernier passage de mises à jour
                              (défaut : 30 — critique au double)
      --max-paquets <n>       Nombre maximal de mises à jour en attente
                              (défaut : 20 — critique au double)
      --securite-critique     Une mise à jour de sécurité en attente devient un
                              point critique (code 2) au lieu d'un avertissement
      --json                  Sortie JSON sur stdout (pour supervision)
  -n, --dry-run               N'exécute aucune action modifiante : seule
                              l'option --rafraichir serait concernée
  -q, --quiet                 N'affiche que les avertissements et erreurs
  -v, --verbose               Affiche les commandes exécutées
  -h, --help                  Affiche cette aide

Codes retour :
  0  hôte à jour au regard des seuils
  1  avertissement (retard, paquets, sécurité, redémarrage) ou erreur
  2  critique (seuil doublé, ou sécurité en attente avec --securite-critique)
     ou paramètres invalides

Exemples :
  patch-report.sh
  patch-report.sh --hote srv-web-01 --max-retard 15 --max-paquets 10
  patch-report.sh --json | jq '.mises_a_jour'
  patch-report.sh --securite-critique --max-paquets 0
EOF
}

# --- Arguments ---------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        --hote)            [[ -n "${2:-}" ]] || die_usage "--hote exige un nom"; HOTE="$2"; shift 2 ;;
        --gestionnaire)    [[ -n "${2:-}" ]] || die_usage "--gestionnaire exige un nom"; GESTIONNAIRE_FORCE="$2"; shift 2 ;;
        --rafraichir)      RAFRAICHIR=1; shift ;;
        --max-retard)      [[ -n "${2:-}" ]] || die_usage "--max-retard exige un nombre de jours"; MAX_RETARD="$2"; shift 2 ;;
        --max-paquets)     [[ -n "${2:-}" ]] || die_usage "--max-paquets exige un nombre"; MAX_PAQUETS="$2"; shift 2 ;;
        --securite-critique) SECURITE_CRITIQUE=1; shift ;;
        --json)            FORMAT="json"; shift ;;
        -n|--dry-run)      DRY_RUN=1; shift ;;
        -q|--quiet)        QUIET=1; shift ;;
        -v|--verbose)      VERBOSE=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

# --- Validation des paramètres ----------------------------------------------
if [[ ! "$MAX_RETARD" =~ ^[0-9]+$ ]]; then
    die_usage "--max-retard doit être un nombre entier de jours (reçu : ${MAX_RETARD})"
fi
if [[ ! "$MAX_PAQUETS" =~ ^[0-9]+$ ]]; then
    die_usage "--max-paquets doit être un nombre entier (reçu : ${MAX_PAQUETS})"
fi
if [[ -n "$GESTIONNAIRE_FORCE" ]]; then
    case "$GESTIONNAIRE_FORCE" in
        apt|dnf|yum|pacman|zypper) GESTIONNAIRE="$GESTIONNAIRE_FORCE" ;;
        *) die_usage "--gestionnaire accepte : apt, dnf, yum, pacman, zypper (reçu : ${GESTIONNAIRE_FORCE})" ;;
    esac
fi

# --- Détection ---------------------------------------------------------------
detecter_gestionnaire() {
    if [[ -n "$GESTIONNAIRE" ]]; then
        return 0
    fi
    local candidat
    for candidat in apt-get dnf yum pacman zypper; do
        if command -v "$candidat" >/dev/null 2>&1; then
            case "$candidat" in
                apt-get) GESTIONNAIRE="apt" ;;
                *)       GESTIONNAIRE="$candidat" ;;
            esac
            return 0
        fi
    done
    return 1
}

# --- Collecte : apt ----------------------------------------------------------
collecter_apt() {
    local sortie="" ligne nom
    # --simulate : aucune écriture, aucun verrou, on lit l'état en cache.
    sortie="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null || true)"

    NB_MAJ="$(printf '%s\n' "$sortie" | awk '/^Inst /{n++} END {print n+0}')"
    NB_SEC="$(printf '%s\n' "$sortie" | awk '/^Inst / && tolower($0) ~ /security/ {n++} END {print n+0}')"
    SEC_CONNUE="oui"
    ORIGINE_SEC="dépôts « security » vus dans la simulation apt-get"

    LISTE_MAJ=()
    while IFS= read -r nom; do
        [[ -n "$nom" ]] || continue
        LISTE_MAJ+=("$nom")
    done < <(printf '%s\n' "$sortie" | awk '/^Inst /{print $2}' | head -15)

    if [[ -n "$(find /var/lib/apt/lists -maxdepth 1 -name '*_Packages*' -print -quit 2>/dev/null || true)" ]]; then
        PAQUETS_OK=1
    else
        PAQUETS_OK=0
        DETAIL_INVENTAIRE="aucun index de paquets en cache (/var/lib/apt/lists vide) : lancez --rafraichir"
    fi
}

# --- Collecte : dnf / yum ----------------------------------------------------
# Renvoie le nombre de paquets en attente depuis une sortie « check-update ».
compter_sortie_rpm() {
    awk '$1 ~ /\.[A-Za-z0-9_]+$/ && NF >= 3 {n++} END {print n+0}'
}

collecter_rpm() {
    local outil="$1" rc=0 rc_sec=0 sortie="" sortie_sec="" nom
    sortie="$("$outil" -q --cacheonly check-update 2>/dev/null)" || rc=$?
    case "$rc" in
        0)   NB_MAJ=0; PAQUETS_OK=1 ;;
        100) NB_MAJ="$(printf '%s\n' "$sortie" | compter_sortie_rpm)"; PAQUETS_OK=1 ;;
        *)   NB_MAJ=0; PAQUETS_OK=0
             DETAIL_INVENTAIRE="${outil} : métadonnées indisponibles en cache (${outil} makecache ou --rafraichir)" ;;
    esac

    LISTE_MAJ=()
    while IFS= read -r nom; do
        [[ -n "$nom" ]] || continue
        LISTE_MAJ+=("$nom")
    done < <(printf '%s\n' "$sortie" | awk '$1 ~ /\.[A-Za-z0-9_]+$/ && NF >= 3 {print $1}' | head -15)

    if (( PAQUETS_OK )); then
        sortie_sec="$("$outil" -q --cacheonly check-update --security 2>/dev/null)" || rc_sec=$?
        if (( rc_sec == 0 || rc_sec == 100 )); then
            NB_SEC="$(printf '%s\n' "$sortie_sec" | compter_sortie_rpm)"
            SEC_CONNUE="oui"
            ORIGINE_SEC="option --security de ${outil} (plugin de sécurité)"
        else
            SEC_CONNUE="non"
            ORIGINE_SEC="le plugin de sécurité de ${outil} ne répond pas : distinguer le sécurité n'est pas possible ici"
        fi
    fi
}

# --- Collecte : pacman -------------------------------------------------------
collecter_pacman() {
    local rc=0 sortie="" nom
    sortie="$(pacman -Qu 2>/dev/null)" || rc=$?
    if (( rc == 0 )); then
        NB_MAJ="$(printf '%s\n' "$sortie" | awk 'NF {n++} END {print n+0}')"
        PAQUETS_OK=1
    else
        NB_MAJ=0
        PAQUETS_OK=0
        DETAIL_INVENTAIRE="pacman -Qu a échoué : base de synchronisation absente ou illisible (pacman -Sy ou --rafraichir)"
    fi

    LISTE_MAJ=()
    while IFS= read -r nom; do
        [[ -n "$nom" ]] || continue
        LISTE_MAJ+=("$nom")
    done < <(printf '%s\n' "$sortie" | awk 'NF {print $1}' | head -15)

    # pacman n'associe pas de sévérité à une mise à jour : seul un outil dédié
    # (arch-audit, arch-audit-gtk) sait répondre sur les CVE.
    SEC_CONNUE="non"
    ORIGINE_SEC="pacman ne distingue pas les mises à jour de sécurité (utiliser arch-audit pour les CVE)"
}

# --- Collecte : zypper -------------------------------------------------------
# Compte les lignes de données d'un tableau zypper : la sortie est découpée sur
# le séparateur « | », ce qui rend la position des colonnes indépendante des
# espaces de remplissage (l'en-tête « S | Repository | … » et la ligne de
# tirets sont écartés).
compter_tableau_zypper() {
    awk -F'|' 'NF >= 4 && $1 !~ /^ *S? *$/ && $1 !~ /^[-+ ]*$/ {n++} END {print n+0}'
}

# Extrait la 3e colonne (nom du paquet) d'un tableau zypper
noms_tableau_zypper() {
    awk -F'|' 'NF >= 4 && $1 !~ /^ *S? *$/ && $1 !~ /^[-+ ]*$/ {gsub(/^ +| +$/, "", $3); if ($3 != "") print $3}'
}

collecter_zypper() {
    local rc=0 rc_sec=0 sortie="" sortie_sec="" nom
    sortie="$(zypper --non-interactive --quiet list-updates 2>/dev/null)" || rc=$?
    if (( rc == 0 )); then
        NB_MAJ="$(printf '%s\n' "$sortie" | compter_tableau_zypper)"
        PAQUETS_OK=1
    else
        NB_MAJ=0
        PAQUETS_OK=0
        DETAIL_INVENTAIRE="zypper list-updates a échoué : dépôts non actualisés (zypper refresh ou --rafraichir)"
    fi

    LISTE_MAJ=()
    while IFS= read -r nom; do
        [[ -n "$nom" ]] || continue
        LISTE_MAJ+=("$nom")
    done < <(printf '%s\n' "$sortie" | noms_tableau_zypper | head -15)

    if (( PAQUETS_OK )); then
        sortie_sec="$(zypper --non-interactive --quiet list-patches --category security 2>/dev/null)" || rc_sec=$?
        if (( rc_sec == 0 )); then
            NB_SEC="$(printf '%s\n' "$sortie_sec" | compter_tableau_zypper)"
            SEC_CONNUE="oui"
            ORIGINE_SEC="correctifs de sécurité nécessaires (zypper list-patches --category security)"
        else
            SEC_CONNUE="non"
            ORIGINE_SEC="zypper list-patches indisponible : distinguer le sécurité n'est pas possible ici"
        fi
    fi
}

# --- Collecte : redémarrage --------------------------------------------------
# Détecte un noyau installé plus récent que celui en cours d'exécution. Seuls
# les fichiers /boot/vmlinuz-<version> sont comparés : un nom non versionné
# (vmlinuz-linux sur Arch) ne permet aucune conclusion.
detecter_noyau() {
    local fichier nom courant=""
    NOYAU_EN_COURS="$(uname -r)"
    for fichier in /boot/vmlinuz-*; do
        [[ -e "$fichier" ]] || continue
        nom="${fichier##*/}"
        nom="${nom#vmlinuz-}"
        [[ "$nom" =~ ^[0-9] ]] || continue
        if [[ -z "$courant" ]]; then
            courant="$nom"
        elif [[ "$(printf '%s\n%s\n' "$courant" "$nom" | sort -V | tail -1)" == "$nom" ]]; then
            courant="$nom"
        fi
    done

    if [[ -n "$courant" && "$courant" != "$NOYAU_EN_COURS" ]]; then
        REDEMARRAGE="oui"
        RAISON_REDEMARRAGE="noyau installé ${courant}, noyau en cours ${NOYAU_EN_COURS}"
    fi
}

detecter_redemarrage() {
    local paquets=""
    if [[ -f /var/run/reboot-required || -f /run/reboot-required ]]; then
        REDEMARRAGE="oui"
        RAISON_REDEMARRAGE="fichier reboot-required présent"
        if [[ -r /run/reboot-required.pkgs ]]; then
            paquets="$(tr '\n' ' ' < /run/reboot-required.pkgs)"
            RAISON_REDEMARRAGE="${RAISON_REDEMARRAGE} (paquets : ${paquets% })"
        fi
    fi
    detecter_noyau
}

# --- Collecte : fraîcheur du dernier passage ---------------------------------
candidats_journaux() {
    case "$GESTIONNAIRE" in
        apt)    printf '%s\n' "/var/lib/apt/periodic/update-success-stamp" "/var/log/apt/history.log" ;;
        dnf)    printf '%s\n' "/var/log/dnf.log" "/var/log/dnf.rpm.log" ;;
        yum)    printf '%s\n' "/var/log/yum.log" "/var/log/dnf.log" ;;
        pacman) printf '%s\n' "/var/log/pacman.log" ;;
        zypper) printf '%s\n' "/var/log/zypp/history" ;;
    esac
}

# Date réelle de la dernière opération de paquets, lue dans le CONTENU du journal.
# C'est la seule source fiable : un « history.log » vide mais récent ne dit rien
# de la dernière mise à jour — sa date est celle de la rotation du journal, ce qui
# fait croire à un système à jour (ou en retard) sans rapport avec la réalité.
date_derniere_operation_apt() {
    local fichier ligne date_txt epoch
    while IFS= read -r fichier; do
        [[ -n "$fichier" && -r "$fichier" ]] || continue
        case "$fichier" in
            *.gz) ligne="$(zcat "$fichier" 2>/dev/null | grep -m1 '^Start-Date:' || true)" ;;
            *)    ligne="$(grep -m1 '^Start-Date:' "$fichier" 2>/dev/null || true)" ;;
        esac
        [[ -n "$ligne" ]] || continue
        date_txt="${ligne#Start-Date: }"
        if epoch="$(date -d "$date_txt" +%s 2>/dev/null)"; then
            printf '%s' "$epoch"
            return 0
        fi
    done < <(ls -1t /var/log/apt/history.log /var/log/apt/history.log.*.gz 2>/dev/null)

    # Repli sur dpkg.log, qui enregistre chaque installation et mise à niveau
    while IFS= read -r fichier; do
        [[ -n "$fichier" && -r "$fichier" ]] || continue
        case "$fichier" in
            *.gz) ligne="$(zcat "$fichier" 2>/dev/null | grep -E ' (install|upgrade|remove) ' | tail -1 || true)" ;;
            *)    ligne="$(grep -E ' (install|upgrade|remove) ' "$fichier" 2>/dev/null | tail -1 || true)" ;;
        esac
        [[ -n "$ligne" ]] || continue
        date_txt="${ligne:0:19}"
        if epoch="$(date -d "$date_txt" +%s 2>/dev/null)"; then
            printf '%s' "$epoch"
            return 0
        fi
    done < <(ls -1t /var/log/dpkg.log /var/log/dpkg.log.*.gz 2>/dev/null)

    return 1
}

detecter_derniere_maj() {
    local fichier=""
    local tampon="" dernier=0 source_du_journal=""

    # 1. Priorité au contenu du journal (fiable)
    if [[ "$GESTIONNAIRE" == "apt" ]]; then
        tampon="$(date_derniere_operation_apt || true)"
        if [[ -n "$tampon" ]]; then
            dernier="$tampon"
            source_du_journal="/var/log/apt/history.log (dernière opération enregistrée)"
        fi
    elif [[ "$GESTIONNAIRE" == "pacman" && -r /var/log/pacman.log ]]; then
        tampon="$(grep -oE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}' /var/log/pacman.log 2>/dev/null | tail -1 | tr -d '[' || true)"
        if [[ -n "$tampon" ]] && epoch_pacman="$(date -d "$tampon" +%s 2>/dev/null)"; then
            dernier="$epoch_pacman"
            source_du_journal="/var/log/pacman.log (dernière opération enregistrée)"
        fi
    fi

    # 2. Repli : date de modification du journal le plus récent. Approximatif, et
    #    annoncé comme tel — c'est ce repli qui produisait un chiffre trompeur.
    if (( dernier == 0 )); then
        while IFS= read -r fichier; do
            [[ -n "$fichier" ]] || continue
            [[ -f "$fichier" ]] || continue
            tampon="$(stat -c %Y "$fichier" 2>/dev/null || true)"
            [[ -n "$tampon" ]] || continue
            if (( tampon > dernier )); then
                dernier="$tampon"
                source_du_journal="$fichier"
            fi
        done < <(candidats_journaux)

        if (( dernier > 0 )); then
            source_du_journal="${source_du_journal} (date du fichier — approximatif)"
        fi
    fi

    # Repli : aucune trace de journal, on regarde la fraîcheur des index en cache
    if (( dernier == 0 )) && [[ "$GESTIONNAIRE" == "apt" ]]; then
        tampon="$(find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1 || true)"
        if [[ -n "$tampon" ]]; then
            dernier="${tampon%%.*}"
            source_du_journal="/var/lib/apt/lists (index en cache)"
        fi
    fi

    if (( dernier > 0 )); then
        EPOCH_MAJ="$dernier"
        SOURCE_MAJ="$source_du_journal"
        RETARD_JOURS=$(( ( $(date +%s) - dernier ) / 86400 ))
        RETARD_JSON="$RETARD_JOURS"
    fi
}

# --- Collecte : mises à jour automatiques ------------------------------------
timer_systemd_present() {
    local motif="$1" fichier
    for fichier in /etc/systemd/system/"$motif" /usr/lib/systemd/system/"$motif" /lib/systemd/system/"$motif"; do
        if [[ -e "$fichier" ]]; then
            printf '%s' "${fichier##*/}"
            return 0
        fi
    done
    return 1
}

detecter_maj_auto() {
    local fichier="" auto_conf=""
    case "$GESTIONNAIRE" in
        apt)
            for fichier in /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/*auto-upgrades; do
                [[ -f "$fichier" ]] || continue
                auto_conf="$fichier"
                break
            done
            if [[ -n "$auto_conf" ]] && grep -Eq 'APT::Periodic::Unattended-Upgrade[[:space:]]+"[1-9]' "$auto_conf"; then
                MAJ_AUTO="oui"
                DETAIL_MAJ_AUTO="unattended-upgrades actif (${auto_conf})"
            elif [[ -n "$(timer_systemd_present 'unattended-upgrades.service' || true)" ]]; then
                MAJ_AUTO="oui"
                DETAIL_MAJ_AUTO="unattended-upgrades présent (unité systemd)"
            elif [[ -n "$(timer_systemd_present 'apt-daily-upgrade.timer' || true)" ]]; then
                MAJ_AUTO="oui"
                DETAIL_MAJ_AUTO="apt-daily-upgrade.timer présent (téléchargement/installation planifiés)"
            else
                MAJ_AUTO="non"
                DETAIL_MAJ_AUTO="aucune mise à jour automatique détectée (unattended-upgrades absent ou désactivé)"
            fi ;;
        dnf|yum)
            if [[ -n "$(timer_systemd_present 'dnf-automatic.timer' || true)" || -n "$(timer_systemd_present 'yum-cron.service' || true)" ]]; then
                MAJ_AUTO="oui"
                DETAIL_MAJ_AUTO="dnf-automatic / yum-cron présent"
            else
                MAJ_AUTO="non"
                DETAIL_MAJ_AUTO="aucune mise à jour automatique détectée (dnf-automatic absent)"
            fi ;;
        pacman)
            if [[ -n "$(timer_systemd_present 'pacman-filesdb-refresh.timer' || true)" \
               || -n "$(timer_systemd_present 'reflector.timer' || true)" \
               || -n "$(timer_systemd_present 'arch-update.timer' || true)" ]]; then
                MAJ_AUTO="oui"
                DETAIL_MAJ_AUTO="minuterie systemd détectée (rafraîchissement automatique)"
            else
                MAJ_AUTO="non"
                DETAIL_MAJ_AUTO="aucune minuterie de mise à jour détectée (pacman est manuel par conception)"
            fi ;;
        zypper)
            if [[ -n "$(timer_systemd_present 'zypper-download.timer' || true)" \
               || -n "$(timer_systemd_present 'zypper-automirror.timer' || true)" \
               || -n "$(timer_systemd_present 'zypp-autorefresh.timer' || true)" ]]; then
                MAJ_AUTO="oui"
                DETAIL_MAJ_AUTO="minuterie zypper détectée"
            else
                MAJ_AUTO="non"
                DETAIL_MAJ_AUTO="aucune minuterie zypper détectée"
            fi ;;
    esac
}

# --- Instrumentation ---------------------------------------------------------
ajouter() {
    local nom="$1" statut="$2" detail="$3"
    case "$statut" in
        OK)   NB_OK=$(( NB_OK + 1 )) ;;
        WARN) NB_WARN=$(( NB_WARN + 1 )) ;;
        CRIT) NB_CRIT=$(( NB_CRIT + 1 )) ;;
    esac
    RESULTATS+=("${nom}|${statut}|${detail}")

    if [[ "$FORMAT" == "texte" ]] && { (( ! QUIET )) || [[ "$statut" != "OK" ]]; }; then
        local couleur="$C_OK" symbole="OK"
        if [[ "$statut" == "WARN" ]]; then
            couleur="$C_WARN"; symbole="ATTENTION"
        elif [[ "$statut" == "CRIT" ]]; then
            couleur="$C_ERR"; symbole="CRITIQUE"
        fi
        printf '  %s%-9s%s %-28s %s\n' "$couleur" "$symbole" "$C_RESET" "$nom" "$detail" >&2
    fi
}

echapper_json() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# --- Sortie ------------------------------------------------------------------
emettre_json() {
    local nom="" statut="" detail="" ligne="" premier=1
    local bool_sec="false" bool_raf="false" bool_reboot="false" bool_auto="false"
    local bool_inventaire="false" bool_securite_critique="false"
    local date_maj="inconnue"

    if [[ "$SEC_CONNUE" == "oui" ]]; then bool_sec="true"; fi
    if (( RAFRAICHIR )); then bool_raf="true"; fi
    if [[ "$REDEMARRAGE" == "oui" ]]; then bool_reboot="true"; fi
    if [[ "$MAJ_AUTO" == "oui" ]]; then bool_auto="true"; fi
    if [[ "$PAQUETS_OK" == "1" ]]; then bool_inventaire="true"; fi
    if (( SECURITE_CRITIQUE )); then bool_securite_critique="true"; fi
    if [[ -n "$EPOCH_MAJ" ]]; then date_maj="$(date --iso-8601=seconds -d "@${EPOCH_MAJ}")"; fi

    printf '{\n'
    printf '  "hote": "%s",\n' "$(echapper_json "$HOTE")"
    printf '  "date": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "gestionnaire": "%s",\n' "$GESTIONNAIRE"
    printf '  "rafraichissement_effectue": %s,\n' "$bool_raf"
    printf '  "mises_a_jour": {"total": %d, "securite": %d, "securite_connue": %s, "inventaire_disponible": %s},\n' \
        "$NB_MAJ" "$NB_SEC" "$bool_sec" "$bool_inventaire"
    printf '  "derniere_maj": {"date": "%s", "source": "%s", "retard_jours": %s},\n' \
        "$date_maj" "$(echapper_json "${SOURCE_MAJ:-inconnue}")" "$RETARD_JSON"
    printf '  "redemarrage_requis": {"requis": %s, "raison": "%s"},\n' "$bool_reboot" "$(echapper_json "${RAISON_REDEMARRAGE:-aucune}")"
    printf '  "mises_a_jour_automatiques": {"actives": %s, "detail": "%s"},\n' "$bool_auto" "$(echapper_json "$DETAIL_MAJ_AUTO")"
    printf '  "noyau": {"en_cours": "%s"},\n' "$(echapper_json "${NOYAU_EN_COURS:-inconnu}")"
    printf '  "seuils": {"max_retard_jours": %d, "max_paquets": %d, "securite_critique": %s},\n' \
        "$MAX_RETARD" "$MAX_PAQUETS" "$bool_securite_critique"
    printf '  "resume": {"ok": %d, "avertissement": %d, "critique": %d},\n' "$NB_OK" "$NB_WARN" "$NB_CRIT"
    printf '  "checks": [\n'
    for ligne in "${RESULTATS[@]:-}"; do
        [[ -n "$ligne" ]] || continue
        IFS='|' read -r nom statut detail <<< "$ligne"
        if (( ! premier )); then printf ',\n'; fi
        premier=0
        printf '    {"nom": "%s", "statut": "%s", "detail": "%s"}' \
            "$(echapper_json "$nom")" "$statut" "$(echapper_json "$detail")"
    done
    printf '\n  ]\n}\n'
}

emettre_sortie() {
    if [[ "$FORMAT" == "json" ]]; then
        emettre_json
        return 0
    fi

    printf '\n%sRésumé : %d OK, %d avertissement(s), %d critique(s) — %s%s\n' \
        "$C_INFO" "$NB_OK" "$NB_WARN" "$NB_CRIT" "$HOTE" "$C_RESET" >&2
    if (( VERBOSE )) && (( ${#LISTE_MAJ[@]} > 0 )); then
        printf '%sPaquets en attente (extrait) : %s%s\n' "$C_DIM" "${LISTE_MAJ[*]}" "$C_RESET" >&2
    fi
}

terminer() {
    emettre_sortie
    if (( NB_CRIT > 0 )); then exit 2; fi
    if (( NB_WARN > 0 )); then exit 1; fi
    exit 0
}

# --- Démarrage ---------------------------------------------------------------
require_cmd awk stat find sort head grep

if [[ -z "$HOTE" ]]; then
    HOTE="$(hostname -f 2>/dev/null || hostname)"
fi

if ! detecter_gestionnaire; then
    die "Aucun gestionnaire de paquets reconnu (apt, dnf, yum, pacman, zypper) sur cet hôte."
fi

case "$GESTIONNAIRE" in
    apt)    CMD="apt-get" ;;
    dnf)    CMD="dnf" ;;
    yum)    CMD="yum" ;;
    pacman) CMD="pacman" ;;
    zypper) CMD="zypper" ;;
esac

if ! command -v "$CMD" >/dev/null 2>&1; then
    if [[ -n "$GESTIONNAIRE_FORCE" ]]; then
        die_usage "--gestionnaire ${GESTIONNAIRE} demandé mais la commande ${CMD} est absente de cet hôte."
    fi
    die "Gestionnaire ${GESTIONNAIRE} détecté mais commande ${CMD} introuvable."
fi

init_script "" ""

log_info "hôte        : ${HOTE}"
log_info "gestionnaire: ${GESTIONNAIRE} (${CMD})"
if (( RAFRAICHIR )); then
    log_warn "le cache des paquets sera actualisé : --rafraichir écrit sur le système"
else
    log_info "lecture seule : données en cache uniquement (--rafraichir pour actualiser)"
fi

# --- 1/4 Gestionnaire et actualisation ---------------------------------------
log_step "1/4 Gestionnaire de paquets"
ajouter "gestionnaire" "OK" "${GESTIONNAIRE} détecté (${CMD})"

if (( RAFRAICHIR )); then
    if (( ! DRY_RUN )); then
        require_root
    fi
    case "$GESTIONNAIRE" in
        apt)    run_sh "apt-get update" ;;
        dnf)    run_sh "dnf -q makecache" ;;
        yum)    run_sh "yum -q makecache" ;;
        pacman)
            log_warn "pacman -Sy seul laisse la base de paquets en état partiel : enchaînez avec pacman -Su"
            run_sh "pacman -Sy" ;;
        zypper) run_sh "zypper --non-interactive refresh" ;;
    esac
    ajouter "rafraichissement" "OK" "cache actualisé par ${GESTIONNAIRE}"
fi

# --- 2/4 Mises à jour disponibles --------------------------------------------
log_step "2/4 Mises à jour disponibles"
case "$GESTIONNAIRE" in
    apt)    collecter_apt ;;
    dnf|yum) collecter_rpm "$GESTIONNAIRE" ;;
    pacman) collecter_pacman ;;
    zypper) collecter_zypper ;;
esac

if (( PAQUETS_OK )); then
    if (( NB_MAJ > MAX_PAQUETS * 2 )); then
        ajouter "mises_a_jour" "CRIT" "${NB_MAJ} mise(s) à jour en attente (seuil ${MAX_PAQUETS}, critique $(( MAX_PAQUETS * 2 )))"
    elif (( NB_MAJ > MAX_PAQUETS )); then
        ajouter "mises_a_jour" "WARN" "${NB_MAJ} mise(s) à jour en attente (seuil ${MAX_PAQUETS})"
    else
        ajouter "mises_a_jour" "OK" "${NB_MAJ} mise(s) à jour en attente (seuil ${MAX_PAQUETS})"
    fi
else
    ajouter "mises_a_jour" "WARN" "inventaire indisponible : ${DETAIL_INVENTAIRE}"
fi

if [[ "$SEC_CONNUE" == "oui" ]]; then
    if (( NB_SEC == 0 )); then
        ajouter "mises_a_jour_securite" "OK" "aucune mise à jour de sécurité en attente (${ORIGINE_SEC})"
    elif (( SECURITE_CRITIQUE )); then
        ajouter "mises_a_jour_securite" "CRIT" "${NB_SEC} mise(s) à jour de sécurité en attente (${ORIGINE_SEC})"
    else
        ajouter "mises_a_jour_securite" "WARN" "${NB_SEC} mise(s) à jour de sécurité en attente (${ORIGINE_SEC})"
    fi
else
    ajouter "mises_a_jour_securite" "WARN" "sécurité non distinguée par ${GESTIONNAIRE} : ${ORIGINE_SEC}"
fi

# --- 3/4 Redémarrage, fraîcheur, automatisation ------------------------------
log_step "3/4 Redémarrage, fraîcheur des données, automatisation"

detecter_redemarrage
if [[ "$REDEMARRAGE" == "oui" ]]; then
    ajouter "redemarrage" "WARN" "redémarrage nécessaire : ${RAISON_REDEMARRAGE}"
else
    ajouter "redemarrage" "OK" "non requis (noyau en cours ${NOYAU_EN_COURS})"
fi

detecter_derniere_maj
if [[ -n "$EPOCH_MAJ" ]]; then
    DETAIL_MAJ="dernier passage il y a ${RETARD_JOURS} jour(s) — $(date --iso-8601=seconds -d "@${EPOCH_MAJ}") (${SOURCE_MAJ})"
    if (( RETARD_JOURS > MAX_RETARD * 2 )); then
        ajouter "derniere_maj" "CRIT" "${DETAIL_MAJ} > ${MAX_RETARD} jours"
    elif (( RETARD_JOURS > MAX_RETARD )); then
        ajouter "derniere_maj" "WARN" "${DETAIL_MAJ} > ${MAX_RETARD} jours"
    else
        ajouter "derniere_maj" "OK" "$DETAIL_MAJ"
    fi
else
    ajouter "derniere_maj" "WARN" "date du dernier passage de mises à jour introuvable (aucun journal ni index exploitable)"
fi

detecter_maj_auto
if [[ "$MAJ_AUTO" == "oui" ]]; then
    ajouter "mises_a_jour_automatiques" "OK" "$DETAIL_MAJ_AUTO"
else
    ajouter "mises_a_jour_automatiques" "WARN" "$DETAIL_MAJ_AUTO"
fi

# --- 4/4 Bilan ---------------------------------------------------------------
log_step "4/4 Bilan"
if (( NB_CRIT > 0 )); then
    fin_script "État des correctifs : point(s) critique(s) sur ${HOTE}"
elif (( NB_WARN > 0 )); then
    fin_script "État des correctifs : avertissement(s) sur ${HOTE}"
else
    fin_script "État des correctifs : conforme sur ${HOTE}"
fi
terminer
