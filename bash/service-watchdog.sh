#!/usr/bin/env bash
# =============================================================================
# service-watchdog.sh — Surveillance et redémarrage automatique de services
# -----------------------------------------------------------------------------
# Contrôle l'état de services systemd, de conteneurs Docker et de points de
# terminaison HTTP, redémarre automatiquement ce qui est arrêté dans la limite
# d'un quota horaire, notifie (webhook HTTP et/ou courriel) et journalise
# chaque incident dans un fichier d'historique CSV.
#
# Pourquoi : un service qui tombe à 3 h du matin et reste arrêté jusqu'à
# l'arrivée du premier administrateur, c'est plusieurs heures d'indisponibilité
# pour un redémarrage qui aurait pris deux secondes. Une usine de supervision
# sait le faire, mais un script autonome s'installe partout — y compris sur un
# hôte sans agent, depuis une tâche cron ou une minuterie systemd.
#
# Le quota horaire (--max-redemarrages) protège de l'effet « boucle de
# redémarrage » : au-delà du quota, le script alerte un humain au lieu de
# masquer une panne réelle derrière des relances infinies.
#
# Les URL HTTP sont surveillées mais jamais « redémarrées » : aucune action
# générique n'a de sens sur une URL. Pour aller plus loin, encapsulez le
# service dans une unité systemd et surveillez l'unité.
#
# Codes retour :
#   0 = toutes les cibles sont saines (ou ont été récupérées)
#   1 = au moins une cible est encore en panne en fin d'exécution
#   2 = paramètres invalides
#
# Colonnes du fichier d'historique CSV :
#   horodatage,epoch,cible,type,action,resultat,message
#
# Exemples :
#   ./service-watchdog.sh --service nginx --service ssh
#   ./service-watchdog.sh --conteneur nextcloud-app --http https://exemple.fr/login
#   ./service-watchdog.sh --service nginx --max-redemarrages 2 --dry-run
#   ./service-watchdog.sh --service nginx --webhook https://exemple.fr/hooks/alertes
#   ./service-watchdog.sh --service nginx --mail astreinte@exemple.fr
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# --- Valeurs par défaut ------------------------------------------------------
readonly HISTORIQUE_DEFAUT="/var/log/service-watchdog.csv"
readonly ATTENTE_SERVICE=3      # secondes avant de vérifier un service relancé
readonly FENETRE_QUOTA=3600     # fenêtre glissante du quota : 1 heure
readonly DELAI_HTTP=10          # délai maximal d'une requête HTTP

SERVICES=()
CONTENEURS=()
URLS=()
MAX_REDEMARRAGES=3
HISTORIQUE="$HISTORIQUE_DEFAUT"
WEBHOOK=""
COURRIEL=""

# Compteurs et rapport d'incidents (alimentés pendant les contrôles)
NB_CIBLES=0
INCIDENTS=0
ECHECS=0
RAPPORT=()

usage() {
    entete_script "Surveille des services, conteneurs et URL, et redémarre ce qui est arrêté."
    cat >&2 <<'EOF'

Usage :
  service-watchdog.sh [options] (--service | --conteneur | --http) ...

Cibles (au moins une, répétables) :
      --service <unité>          Service systemd à surveiller
      --conteneur <nom>          Conteneur Docker à surveiller
      --http <url>               URL à tester (surveillance seule, pas de relance)

Options :
      --max-redemarrages <n>     Redémarrages autorisés par cible et par heure
                                 (défaut : 3)
      --historique <fichier>     Fichier CSV d'historique des incidents
                                 (défaut : /var/log/service-watchdog.csv)
      --webhook <url>            URL appelée en POST (JSON) en cas d'incident
      --mail <adresse>           Adresse destinataire d'un courriel d'alerte
  -n, --dry-run                  Simulation : aucune relance, aucune écriture
  -q, --quiet                    N'affiche que les avertissements et erreurs
  -v, --verbose                  Affiche le détail des contrôles
  -h, --help                     Affiche cette aide

Codes retour :
  0  toutes les cibles sont saines (ou ont été récupérées)
  1  au moins une cible est encore en panne
  2  mauvaise utilisation (paramètres manquants ou invalides)

Comportement :
  Un service systemd ou un conteneur Docker arrêté est relancé, au plus
  --max-redemarrages fois sur l'heure glissante écoulée (redémarrages comptés
  dans le fichier d'historique). Au-delà du quota, seule l'alerte est émise.
  Une URL qui répond 5xx ou ne répond pas est signalée ; une URL qui répond
  4xx n'est qu'un avertissement (401/403 sont parfois normaux).
  En mode simulation, rien n'est relancé : une cible en panne reste comptée
  comme non récupérée et le code retour est donc 1.

Exemples :
  service-watchdog.sh --service nginx --service ssh --max-redemarrages 2
  service-watchdog.sh --conteneur nextcloud-app --http https://exemple.fr
  service-watchdog.sh --service nginx --webhook https://exemple.fr/hooks/alertes
EOF
}

# --- Arguments ---------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        --service)          [[ -n "${2:-}" ]] || die_usage "--service exige un nom d'unité"; SERVICES+=("$2"); shift 2 ;;
        --conteneur)        [[ -n "${2:-}" ]] || die_usage "--conteneur exige un nom"; CONTENEURS+=("$2"); shift 2 ;;
        --http)             [[ -n "${2:-}" ]] || die_usage "--http exige une URL"; URLS+=("$2"); shift 2 ;;
        --max-redemarrages) [[ -n "${2:-}" ]] || die_usage "--max-redemarrages exige un entier"; MAX_REDEMARRAGES="$2"; shift 2 ;;
        --historique)       [[ -n "${2:-}" ]] || die_usage "--historique exige un chemin"; HISTORIQUE="$2"; shift 2 ;;
        --webhook)          [[ -n "${2:-}" ]] || die_usage "--webhook exige une URL"; WEBHOOK="$2"; shift 2 ;;
        --mail)             [[ -n "${2:-}" ]] || die_usage "--mail exige une adresse"; COURRIEL="$2"; shift 2 ;;
        -n|--dry-run)       DRY_RUN=1; shift ;;
        -q|--quiet)         QUIET=1; shift ;;
        -v|--verbose)       VERBOSE=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

# --- Validation des paramètres ----------------------------------------------
if (( ${#SERVICES[@]} + ${#CONTENEURS[@]} + ${#URLS[@]} == 0 )); then
    usage
    die_usage "Indiquez au moins une cible : --service, --conteneur ou --http."
fi

if [[ ! "$MAX_REDEMARRAGES" =~ ^[0-9]+$ ]]; then
    die_usage "--max-redemarrages exige un entier positif (reçu : ${MAX_REDEMARRAGES})"
fi
if (( MAX_REDEMARRAGES < 1 )); then
    die_usage "--max-redemarrages doit valoir au moins 1."
fi

if [[ -n "$WEBHOOK" ]] && [[ ! "$WEBHOOK" =~ ^https?:// ]]; then
    die_usage "--webhook exige une URL en http:// ou https:// (reçu : ${WEBHOOK})"
fi

if [[ -n "$COURRIEL" ]] && [[ ! "$COURRIEL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    die_usage "--mail exige une adresse de la forme utilisateur@domaine (reçu : ${COURRIEL})"
fi

# --- Dépendances -------------------------------------------------------------
require_root
require_cmd awk
require_cmd date
if (( ${#SERVICES[@]} > 0 )); then
    require_cmd systemctl
fi
if (( ${#CONTENEURS[@]} > 0 )); then
    require_cmd docker
fi
if (( ${#URLS[@]} > 0 )) || [[ -n "$WEBHOOK" ]]; then
    require_cmd curl
fi
if [[ -n "$COURRIEL" ]]; then
    require_cmd mail
fi

init_script "/var/log/service-watchdog.log" "/var/run/service-watchdog.lock"

DEBUT="$(date +%s)"

# --- Historique CSV ----------------------------------------------------------
# Crée le fichier d'historique avec son en-tête s'il n'existe pas encore.
preparer_historique() {
    if (( DRY_RUN )); then
        log_debug "[simulation] historique non modifié : ${HISTORIQUE}"
        return 0
    fi
    if [[ ! -f "$HISTORIQUE" ]]; then
        mkdir -p "$(dirname "$HISTORIQUE")"
        printf '%s\n' "horodatage,epoch,cible,type,action,resultat,message" > "$HISTORIQUE"
        log_info "historique créé : ${HISTORIQUE}"
    fi
    if [[ ! -w "$HISTORIQUE" ]]; then
        die "Fichier d'historique non inscriptible : ${HISTORIQUE}"
    fi
}

# Ajoute une ligne d'incident. Le message est purgé de ses virgules et de ses
# sauts de ligne pour garantir un enregistrement CSV par incident.
journaliser() {
    local cible="$1" type="$2" action="$3" resultat="$4" message="$5"
    message="${message//,/;}"
    message="${message//$'\n'/ }"
    message="${message//$'\r'/ }"
    if (( DRY_RUN )); then
        log_debug "[simulation] historique : ${cible},${type},${action},${resultat},${message}"
        return 0
    fi
    printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S')" "$(date +%s)" \
        "$cible" "$type" "$action" "$resultat" "$message" >> "$HISTORIQUE"
}

# Joint des arguments par une espace. Nécessaire car l'IFS global vaut
# « saut de ligne, tabulation » : « $* » produirait un message multiligne,
# donc un enregistrement CSV éclaté sur plusieurs lignes.
joindre() {
    local IFS=' '
    printf '%s' "$*"
}

# Nombre de redémarrages tentés sur une cible durant la fenêtre glissante
compter_redemarrages() {
    local cible="$1"
    if [[ ! -r "$HISTORIQUE" ]]; then
        printf '0\n'
        return 0
    fi
    awk -F, -v now="$DEBUT" -v cible="$cible" -v fenetre="$FENETRE_QUOTA" '
        $3 == cible && $5 == "redemarrage" && ($2 + 0) > (now - fenetre) { n++ }
        END { print n + 0 }
    ' "$HISTORIQUE"
}

# --- Notification ------------------------------------------------------------
# Convertit un texte lu sur l'entrée standard en chaîne JSON échappée.
json_chaine() {
    awk '
        function echappe(s,   i, c, out) {
            out = ""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "\\")      { out = out "\\\\" }
                else if (c == "\"") { out = out "\\\"" }
                else if (c == "\t") { out = out "\\t" }
                else                { out = out c }
            }
            return out
        }
        NR == 1 { texte = $0; next }
        { texte = texte "\n" $0 }
        END { printf "\"%s\"", echappe(texte) }
    '
}

notifier() {
    local sujet corps charge hote_json
    if (( ${#RAPPORT[@]} == 0 )); then
        return 0
    fi

    sujet="[${SCRIPT_NAME}] ${INCIDENTS} incident(s) sur $(hostname)"
    corps="$(printf '%s\n' "${RAPPORT[@]}")"

    if [[ -n "$WEBHOOK" ]]; then
        hote_json="$(printf '%s' "$(hostname)" | json_chaine)"
        charge="$(printf '{"hote":%s,"date":%s,"incidents":%d,"message":%s}' \
            "$hote_json" \
            "$(printf '%s' "$(date --iso-8601=seconds)" | json_chaine)" \
            "$INCIDENTS" \
            "$(printf '%s\n' "${RAPPORT[@]}" | json_chaine)")"
        if (( DRY_RUN )); then
            log_info "[simulation] POST ${WEBHOOK} (charge utile JSON non envoyée)"
        elif curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
                --data "$charge" "$WEBHOOK" >/dev/null; then
            log_ok "Notification webhook envoyée à ${WEBHOOK}"
        else
            log_warn "Échec de la notification webhook vers ${WEBHOOK}"
        fi
    fi

    if [[ -n "$COURRIEL" ]]; then
        if (( DRY_RUN )); then
            log_info "[simulation] courriel à ${COURRIEL} : ${sujet}"
        elif printf '%s\n' "$corps" | mail -s "$sujet" "$COURRIEL"; then
            log_ok "Notification envoyée à ${COURRIEL}"
        else
            log_warn "Échec de l'envoi du courriel à ${COURRIEL} (agent SMTP absent ?)"
        fi
    fi
}

# Lance une commande via « run » (le mode simulation reste donc respecté) en
# forçant un IFS d'espace le temps de l'appel : l'IFS global du dépôt
# (« saut de ligne, tabulation ») ferait afficher la commande sur plusieurs
# lignes dans le journal et dans la sortie du mode simulation.
lancer() {
    IFS=' ' run "$@"
}

# --- Redémarrage sous quota --------------------------------------------------
# tenter_redemarrage <cible> <type> <commande...>
tenter_redemarrage() {
    local cible="$1" type="$2"
    shift 2
    local effectues

    effectues="$(compter_redemarrages "$cible")"
    if (( effectues >= MAX_REDEMARRAGES )); then
        log_error "${cible} : quota de ${MAX_REDEMARRAGES} redémarrage(s) par heure atteint, intervention manuelle nécessaire"
        journaliser "$cible" "$type" "redemarrage" "refuse" \
            "quota horaire atteint (${effectues} dans l'heure)"
        RAPPORT+=("${cible} : quota horaire atteint, redémarrage abandonné")
        return 1
    fi

    log_warn "${cible} : redémarrage tenté (${effectues}/${MAX_REDEMARRAGES} sur l'heure écoulée)"
    if ! lancer "$@"; then
        log_error "${cible} : la commande de redémarrage a échoué"
        journaliser "$cible" "$type" "redemarrage" "echec" "commande en échec : $(joindre "$@")"
        return 1
    fi

    journaliser "$cible" "$type" "redemarrage" "tente" "commande : $(joindre "$@")"
    return 0
}

# --- Vérification de la reprise ---------------------------------------------
verifier_recuperation_service() {
    local svc="$1"
    if (( DRY_RUN )); then
        log_info "[simulation] état de ${svc} non vérifié (aucune relance réelle)"
        return 1
    fi
    sleep "$ATTENTE_SERVICE"
    if [[ "$(systemctl is-active "$svc" 2>/dev/null || true)" == "active" ]]; then
        return 0
    fi
    return 1
}

verifier_recuperation_conteneur() {
    local ct="$1"
    if (( DRY_RUN )); then
        log_info "[simulation] état de ${ct} non vérifié (aucune relance réelle)"
        return 1
    fi
    sleep "$ATTENTE_SERVICE"
    if [[ "$(docker inspect --format '{{.State.Running}}' "$ct" 2>/dev/null || true)" == "true" ]]; then
        return 0
    fi
    return 1
}

# --- Contrôles ---------------------------------------------------------------
controler_service() {
    local svc="$1" etat cible
    cible="service:${svc}"

    if ! systemctl cat "$svc" >/dev/null 2>&1; then
        log_error "Unité systemd introuvable : ${svc}"
        journaliser "$cible" "service" "detection" "absente" "unité systemd inexistante"
        RAPPORT+=("service ${svc} : unité introuvable")
        INCIDENTS=$(( INCIDENTS + 1 ))
        ECHECS=$(( ECHECS + 1 ))
        return 1
    fi

    etat="$(systemctl is-active "$svc" 2>/dev/null || true)"
    if [[ "$etat" == "active" ]]; then
        log_debug "service ${svc} : actif"
        return 0
    fi

    log_warn "service ${svc} : état « ${etat:-inconnu} »"
    INCIDENTS=$(( INCIDENTS + 1 ))
    RAPPORT+=("service ${svc} : ${etat:-inconnu}")
    journaliser "$cible" "service" "detection" "panne" "état ${etat:-inconnu}"

    if tenter_redemarrage "$cible" "service" systemctl restart "$svc"; then
        if verifier_recuperation_service "$svc"; then
            log_ok "service ${svc} : récupéré"
            journaliser "$cible" "service" "verification" "ok" "service de nouveau actif"
            return 0
        fi
    fi

    log_error "service ${svc} : toujours en panne"
    journaliser "$cible" "service" "verification" "echec" "service toujours inactif"
    ECHECS=$(( ECHECS + 1 ))
    return 1
}

controler_conteneur() {
    local ct="$1" etat cible
    cible="conteneur:${ct}"

    if ! docker inspect --format '{{.State.Running}}' "$ct" >/dev/null 2>&1; then
        log_error "Conteneur Docker introuvable : ${ct}"
        journaliser "$cible" "conteneur" "detection" "absente" "conteneur inexistant"
        RAPPORT+=("conteneur ${ct} : inexistant")
        ECHECS=$(( ECHECS + 1 ))
        return 1
    fi

    if docker inspect --format '{{.State.Running}}' "$ct" 2>/dev/null | grep -qx true; then
        log_debug "conteneur ${ct} : en marche"
        return 0
    fi

    etat="$(docker inspect --format '{{.State.Status}}' "$ct" 2>/dev/null || printf 'inconnu')"
    log_warn "conteneur ${ct} : état « ${etat} »"
    INCIDENTS=$(( INCIDENTS + 1 ))
    RAPPORT+=("conteneur ${ct} : ${etat}")
    journaliser "$cible" "conteneur" "detection" "panne" "état ${etat}"

    if tenter_redemarrage "$cible" "conteneur" docker start "$ct"; then
        if verifier_recuperation_conteneur "$ct"; then
            log_ok "conteneur ${ct} : récupéré"
            journaliser "$cible" "conteneur" "verification" "ok" "conteneur de nouveau en marche"
            return 0
        fi
    fi

    log_error "conteneur ${ct} : toujours arrêté"
    journaliser "$cible" "conteneur" "verification" "echec" "conteneur toujours arrêté"
    ECHECS=$(( ECHECS + 1 ))
    return 1
}

controler_http() {
    local url="$1" code temps cible
    cible="http:${url}"

    IFS=' ' read -r code temps <<< "$(curl -s -o /dev/null -m "$DELAI_HTTP" \
        -w '%{http_code} %{time_total}' -L "$url" 2>/dev/null || printf '000 0')"

    if [[ "$code" == "000" ]]; then
        log_error "URL ${url} : aucune réponse (DNS, connexion refusée ou délai dépassé)"
        INCIDENTS=$(( INCIDENTS + 1 ))
        RAPPORT+=("URL ${url} : injoignable")
        journaliser "$cible" "http" "detection" "panne" "aucune réponse après ${DELAI_HTTP}s"
        ECHECS=$(( ECHECS + 1 ))
        return 1
    fi

    if (( code >= 500 )); then
        log_error "URL ${url} : HTTP ${code} en ${temps}s"
        INCIDENTS=$(( INCIDENTS + 1 ))
        RAPPORT+=("URL ${url} : HTTP ${code}")
        journaliser "$cible" "http" "detection" "panne" "code HTTP ${code} en ${temps}s"
        ECHECS=$(( ECHECS + 1 ))
        return 1
    fi

    if (( code >= 400 )); then
        log_warn "URL ${url} : HTTP ${code} en ${temps}s (erreur cliente, à confirmer)"
        journaliser "$cible" "http" "detection" "avertissement" "code HTTP ${code} en ${temps}s"
        return 0
    fi

    log_debug "URL ${url} : HTTP ${code} en ${temps}s"
    return 0
}

# --- Exécution ---------------------------------------------------------------
preparer_historique

if (( ${#SERVICES[@]} > 0 )); then
    log_step "1/3 Services systemd (${#SERVICES[@]})"
    for cible in "${SERVICES[@]}"; do
        NB_CIBLES=$(( NB_CIBLES + 1 ))
        if ! controler_service "$cible"; then
            log_debug "service ${cible} : non sain"
        fi
    done
fi

if (( ${#CONTENEURS[@]} > 0 )); then
    log_step "2/3 Conteneurs Docker (${#CONTENEURS[@]})"
    for cible in "${CONTENEURS[@]}"; do
        NB_CIBLES=$(( NB_CIBLES + 1 ))
        if ! controler_conteneur "$cible"; then
            log_debug "conteneur ${cible} : non sain"
        fi
    done
fi

if (( ${#URLS[@]} > 0 )); then
    log_step "3/3 Points de terminaison HTTP (${#URLS[@]})"
    for cible in "${URLS[@]}"; do
        NB_CIBLES=$(( NB_CIBLES + 1 ))
        if ! controler_http "$cible"; then
            log_debug "URL ${cible} : non saine"
        fi
    done
fi

# --- Notification et bilan ---------------------------------------------------
notifier

printf 'hote=%s cibles=%d incidents=%d echecs=%d historique=%s\n' \
    "$(hostname)" "$NB_CIBLES" "$INCIDENTS" "$ECHECS" "$HISTORIQUE"

if (( ECHECS > 0 )); then
    log_error "Bilan : ${ECHECS} cible(s) en panne sur ${NB_CIBLES}, ${INCIDENTS} incident(s) détecté(s)"
    exit 1
fi

fin_script "Bilan : ${NB_CIBLES} cible(s) saine(s), aucune panne"
exit 0
