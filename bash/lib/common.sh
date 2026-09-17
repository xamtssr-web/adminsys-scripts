#!/usr/bin/env bash
# =============================================================================
# common.sh — Bibliothèque commune pour tous les scripts Bash du dépôt
# -----------------------------------------------------------------------------
# Fournit : journalisation horodatée, gestion d'erreurs avec numéro de ligne,
# mode simulation (--dry-run), vérification des dépendances, verrouillage,
# et fonction de réessai.
#
# Utilisation dans un script :
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#   init_script "mon-script"
# =============================================================================

# Garde-fou : cette bibliothèque ne s'exécute jamais directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "common.sh est une bibliothèque à sourcer, pas à exécuter." >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Mode strict : arrêt sur erreur, variable non définie, erreur dans un pipe
# -E : le trap ERR se propage aussi dans les fonctions et sous-shells
# -----------------------------------------------------------------------------
set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# État global
# -----------------------------------------------------------------------------
DRY_RUN="${DRY_RUN:-0}"          # 1 = n'exécute aucune action modifiante
QUIET="${QUIET:-0}"              # 1 = n'affiche que les avertissements et erreurs
VERBOSE="${VERBOSE:-0}"          # 1 = affiche les commandes exécutées
SCRIPT_NAME="${SCRIPT_NAME:-$(basename "${0:-script}")}"
LOG_FILE="${LOG_FILE:-}"         # fichier de log facultatif
LOCK_FILE="${LOCK_FILE:-}"       # verrou d'exécution unique facultatif
START_TIME="$(date +%s)"

# Couleurs : activées seulement sur un terminal, et si NO_COLOR est absent
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_OK=$'\033[32m'
    C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'
else
    C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""
fi

# -----------------------------------------------------------------------------
# Journalisation — tout part sur stderr pour ne pas polluer les sorties
# exploitables (stdout reste réservé aux données : JSON, CSV, identifiants…)
# -----------------------------------------------------------------------------
_log() {
    local level="$1" color="$2" message="$3"
    local ts line
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    line="$(printf '%s [%-5s] %s' "$ts" "$level" "$message")"
    printf '%s%s%s\n' "$color" "$line" "$C_RESET" >&2
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$line" >> "$LOG_FILE"
    fi
}

log_info()    { (( QUIET ))  || _log INFO  "$C_INFO" "$*"; }
log_ok()      { (( QUIET ))  || _log OK    "$C_OK"   "$*"; }
log_warn()    { _log WARN "$C_WARN" "$*"; }
log_error()   { _log ERROR "$C_ERR"  "$*"; }
log_debug()   { (( VERBOSE )) || return 0; _log DEBUG "$C_DIM" "$*"; }

# Écrit une étape (utile pour un script de plusieurs phases)
log_step() {
    (( QUIET )) || printf '\n%s==> %s%s\n' "$C_INFO" "$*" "$C_RESET" >&2
}

# -----------------------------------------------------------------------------
# Gestion d'erreurs
# -----------------------------------------------------------------------------
# Affiche le contexte exact de l'échec : ligne, commande, code retour
_trap_err() {
    local exit_code=$? line="${1:-?}" cmd="${2:-?}"
    log_error "Échec ligne ${line} (code ${exit_code}) : ${cmd}"
    log_error "Consultez le journal : ${LOG_FILE:-console}"
}
trap '_trap_err "$LINENO" "$BASH_COMMAND"' ERR

# Termine le script proprement avec un message
die() {
    log_error "$*"
    exit 1
}

# Termine le script sur une erreur d'utilisation (paramètres) — code 2
die_usage() {
    log_error "$*"
    exit 2
}

# Vérifie qu'une commande est disponible, sinon arrête le script
require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || die "Commande requise absente : ${cmd}"
    done
}

# Vérifie que le script tourne en root (à appeler seulement si nécessaire)
require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Ce script doit être exécuté en root (sudo)."
}

# -----------------------------------------------------------------------------
# Exécution d'actions — respecte le mode simulation
# -----------------------------------------------------------------------------
# Exécute une commande, ou l'affiche seulement si DRY_RUN=1
run() {
    if (( DRY_RUN )); then
        log_info "[simulation] $*"
        return 0
    fi
    log_debug "exécution : $*"
    "$@"
}

# Idem mais via un shell (nécessaire pour les redirections et les pipes)
run_sh() {
    if (( DRY_RUN )); then
        log_info "[simulation] $*"
        return 0
    fi
    log_debug "exécution : $*"
    bash -c "$*"
}

# Réessaie une commande en cas d'échec (réseau, dépôt, API)
retry() {
    local max_attempts="${1:?}" delay="${2:?}"; shift 2
    local attempt=1
    until "$@"; do
        if (( attempt >= max_attempts )); then
            log_error "Échec après ${attempt} tentative(s) : $*"
            return 1
        fi
        log_warn "Tentative ${attempt}/${max_attempts} échouée, nouvel essai dans ${delay}s"
        sleep "$delay"
        (( attempt++ ))
    done
}

# -----------------------------------------------------------------------------
# Initialisation et clôture
# -----------------------------------------------------------------------------
# init_script [chemin_log] [chemin_verrou]
init_script() {
    local log_path="${1:-}" lock_path="${2:-}"

    if [[ -n "$log_path" ]]; then
        mkdir -p "$(dirname "$log_path")"
        LOG_FILE="$log_path"
        touch "$LOG_FILE"
    fi

    if [[ -n "$lock_path" ]]; then
        mkdir -p "$(dirname "$lock_path")"
        exec 9>"$lock_path" || die "Impossible d'ouvrir le verrou ${lock_path}"
        if ! flock -n 9; then
            die "Une autre instance de ${SCRIPT_NAME} est déjà en cours (verrou ${lock_path})."
        fi
        LOCK_FILE="$lock_path"
    fi

    log_debug "démarrage ${SCRIPT_NAME} (PID $$)"
}

# fin_script [message] — affiche la durée totale
fin_script() {
    local duration=$(( $(date +%s) - START_TIME ))
    log_ok "${1:-${SCRIPT_NAME} terminé} (${duration}s)"
}

# En-tête standard de --help
entete_script() {
    cat >&2 <<EOF
${SCRIPT_NAME}

${1:-}
EOF
}

# -----------------------------------------------------------------------------
# Utilitaires
# -----------------------------------------------------------------------------
# Vérifie si une entrée de tableau contient une valeur
# contient "valeur" "${tableau[@]}"
contient() {
    local needle="$1"; shift
    local item
    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

# Formate des octets en unité lisible (Kio, Mio, Gio)
human_bytes() {
    local bytes="${1:?}"
    awk -v b="$bytes" 'BEGIN {
        split("o Kio Mio Gio Tio", u, " ");
        i = 1;
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        printf "%.1f %s", b, u[i]
    }'
}

# Vérifie qu'un seuil numérique est bien un entier
valider_entier() {
    local valeur="${1:?}" nom="${2:-valeur}"
    if [[ ! "$valeur" =~ ^[0-9]+$ ]]; then
        die "${nom} doit être un entier positif (reçu : ${valeur})"
    fi
}

# Vérifie qu'un port est valide
valider_port() {
    local port="${1:?}"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        die "Port invalide : ${port}"
    fi
}

# Journalise une commande sans l'exécuter — utile en début de script
afficher_plan() {
    printf "%sPlan d'exécution :%s\n" "$C_DIM" "$C_RESET" >&2
    local ligne
    for ligne in "$@"; do
        printf '  - %s\n' "$ligne" >&2
    done
}
