#!/usr/bin/env bash
# =============================================================================
# deploy-docker-stack.sh — Déploiement idempotent d'une pile Docker Compose
# -----------------------------------------------------------------------------
# Vérifie les prérequis, récupère éventuellement le code (git), récupère les
# images, (re)démarre la pile avec --remove-orphans, attend la fin des
# contrôles de santé, vérifie que les conteneurs tournent, et revient
# automatiquement à la version précédente en cas d'échec.
#
# Pourquoi : un « docker compose up -d » lancé à la main ne vérifie rien. Il ne
# dit pas si le fichier .env manquait, si les images ont réellement été
# récupérées, ni si les conteneurs sont sains — et surtout il ne sait pas
# revenir en arrière. Ce script transforme un déploiement en opération
# reproductible, rejouable sans risque (idempotente) et annulable.
#
# Sémantique du retour arrière : le commit courant du dépôt est enregistré
# avant la mise à jour, puis restauré si la pile ne redémarre pas correctement.
# Il exige donc --depot ; sans dépôt git, --sans-rollback est implicite et le
# script le signale clairement.
#
# Codes retour :
#   0 = pile déployée (ou déjà à jour) et saine
#   1 = échec du déploiement (retour arrière effectué ou impossible)
#   2 = paramètres invalides ou prérequis manquants
#
# Exemples :
#   ./deploy-docker-stack.sh --compose /srv/app/docker-compose.yml
#   ./deploy-docker-stack.sh -c /srv/app/compose.yaml --depot /srv/app --branche main
#   ./deploy-docker-stack.sh -c /srv/app/compose.yaml --attente 120 --sans-rollback
#   ./deploy-docker-stack.sh -c /srv/app/compose.yaml --dry-run
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# --- Valeurs par défaut ------------------------------------------------------
readonly ATTENTE_DEFAUT=60      # secondes d'attente des contrôles de santé
readonly INTERVALLE_SONDAGE=3   # secondes entre deux sondages
readonly FICHIERS_COMPOSE=(docker-compose.yml compose.yaml compose.yml)

COMPOSE=""
FICHIER_ENV=""
DEPOT=""
BRANCHE="main"
ATTENTE="$ATTENTE_DEFAUT"
ROLLBACK=1
REV_AVANT=""
REV_APRES=""
NB_CONTENEURS=0

usage() {
    entete_script "Déploie une pile Docker Compose de façon idempotente, avec retour arrière."
    cat >&2 <<'EOF'

Usage :
  deploy-docker-stack.sh --compose <fichier> [options]

Options :
  -c, --compose <fichier>    Fichier compose à déployer (défaut : recherche de
                             docker-compose.yml ou compose.yaml dans le dossier)
      --env <fichier>        Fichier d'environnement (défaut : .env situé à côté
                             du fichier compose) — obligatoire : un déploiement
                             sans variables d'environnement n'est pas reproductible
      --depot <chemin>       Dépôt git à mettre à jour avant le déploiement
      --branche <nom>        Branche à déployer depuis le dépôt (défaut : main)
      --attente <secondes>   Durée maximale d'attente des contrôles de santé
                             (défaut : 60)
      --sans-rollback        N'effectue aucun retour arrière en cas d'échec
  -n, --dry-run              Simulation : affiche le plan sans rien exécuter
  -q, --quiet                N'affiche que les avertissements et erreurs
  -v, --verbose              Affiche les commandes exécutées
  -h, --help                 Affiche cette aide

Codes retour :
  0  pile déployée et saine
  1  échec du déploiement (retour arrière effectué ou impossible)
  2  mauvaise utilisation (paramètres manquants ou invalides)

Exemples :
  deploy-docker-stack.sh --compose /srv/app/docker-compose.yml --attente 90
  deploy-docker-stack.sh -c /srv/app/compose.yaml --depot /srv/app --branche prod
  deploy-docker-stack.sh -c /srv/app/compose.yaml --dry-run
EOF
}

# --- Arguments ---------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        -c|--compose)    [[ -n "${2:-}" ]] || die_usage "-c exige un chemin de fichier compose"; COMPOSE="$2"; shift 2 ;;
        --env)           [[ -n "${2:-}" ]] || die_usage "--env exige un chemin de fichier"; FICHIER_ENV="$2"; shift 2 ;;
        --depot)         [[ -n "${2:-}" ]] || die_usage "--depot exige un chemin de dépôt"; DEPOT="$2"; shift 2 ;;
        --branche)       [[ -n "${2:-}" ]] || die_usage "--branche exige un nom de branche"; BRANCHE="$2"; shift 2 ;;
        --attente)       [[ -n "${2:-}" ]] || die_usage "--attente exige un nombre de secondes"; ATTENTE="$2"; shift 2 ;;
        --sans-rollback) ROLLBACK=0; shift ;;
        -n|--dry-run)    DRY_RUN=1; shift ;;
        -q|--quiet)      QUIET=1; shift ;;
        -v|--verbose)    VERBOSE=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

# --- Validation des paramètres ----------------------------------------------
if [[ ! "$ATTENTE" =~ ^[0-9]+$ ]]; then
    die_usage "--attente exige un entier positif (reçu : ${ATTENTE})"
fi
if [[ ! "$BRANCHE" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    die_usage "--branche contient des caractères inattendus (reçu : ${BRANCHE})"
fi

if [[ -z "$COMPOSE" ]]; then
    for candidat in "${FICHIERS_COMPOSE[@]}"; do
        if [[ -f "$candidat" ]]; then
            COMPOSE="$candidat"
            break
        fi
    done
fi
if [[ -z "$COMPOSE" ]]; then
    die_usage "Aucun fichier compose indiqué ni trouvé dans le dossier courant (--compose)."
fi
if [[ ! -f "$COMPOSE" ]]; then
    die_usage "Fichier compose introuvable : ${COMPOSE}"
fi

if [[ -z "$FICHIER_ENV" ]]; then
    FICHIER_ENV="$(dirname "$COMPOSE")/.env"
fi
if [[ ! -f "$FICHIER_ENV" ]]; then
    die_usage "Fichier d'environnement introuvable : ${FICHIER_ENV} (obligatoire, --env pour le préciser)"
fi
if [[ ! -r "$FICHIER_ENV" ]]; then
    die_usage "Fichier d'environnement illisible : ${FICHIER_ENV}"
fi

if [[ -n "$DEPOT" ]]; then
    if [[ ! -d "$DEPOT/.git" ]]; then
        die_usage "--depot ne désigne pas un dépôt git : ${DEPOT}"
    fi
fi

# --- Dépendances -------------------------------------------------------------
require_cmd docker
if [[ -n "$DEPOT" ]]; then
    require_cmd git
fi
if ! docker compose version >/dev/null 2>&1; then
    die "Le greffon « docker compose » (v2) est absent ou inutilisable."
fi
if ! docker info >/dev/null 2>&1; then
    die "Démon Docker inaccessible : lancez le service, ou vérifiez les droits de l'utilisateur courant."
fi

# --- Journal et verrou -------------------------------------------------------
# Le script peut tourner sans root (groupe docker) : on adapte l'emplacement du
# journal plutôt que d'imposer sudo.
if [[ -w /var/log ]]; then
    JOURNAL="/var/log/deploy-docker-stack.log"
    VERROU="/var/run/deploy-docker-stack.lock"
else
    JOURNAL="${TMPDIR:-/tmp}/deploy-docker-stack.log"
    VERROU="${TMPDIR:-/tmp}/deploy-docker-stack.lock"
fi
init_script "$JOURNAL" "$VERROU"

# --- Utilitaires -------------------------------------------------------------
# Lance une commande via « run » (le mode simulation reste donc respecté) en
# forçant un IFS d'espace le temps de l'appel : l'IFS global du dépôt
# (« saut de ligne, tabulation ») ferait afficher la commande sur plusieurs
# lignes dans le journal et dans la sortie du mode simulation.
lancer() {
    IFS=' ' run "$@"
}

# Enveloppe « docker compose » avec les chemins résolus une fois pour toutes
compose() {
    docker compose --project-directory "$(dirname "$COMPOSE")" \
        --env-file "$FICHIER_ENV" -f "$COMPOSE" "$@"
}

# États des conteneurs de la pile : « nom|sante|en_marche » par ligne
etats_conteneurs() {
    local id
    local -a ids
    mapfile -t ids < <(compose ps -q 2>/dev/null || true)
    for id in "${ids[@]:-}"; do
        if [[ -z "$id" ]]; then
            continue
        fi
        docker inspect --format \
            '{{.Name}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}sans-controle{{end}}|{{.State.Running}}' \
            "$id" 2>/dev/null || true
    done
}

# --- Retour arrière ----------------------------------------------------------
echec_deploiement() {
    local motif="$1"
    log_error "Échec du déploiement : ${motif}"

    if (( DRY_RUN )); then
        exit 1
    fi
    if (( ! ROLLBACK )); then
        log_error "Retour arrière désactivé (--sans-rollback) : la pile reste dans son état actuel."
        exit 1
    fi
    if [[ -z "$DEPOT" ]] || [[ -z "$REV_AVANT" ]]; then
        log_error "Retour arrière impossible sans --depot : aucune version précédente connue."
        exit 1
    fi

    log_step "Retour arrière vers le commit ${REV_AVANT}"
    if ! git -C "$DEPOT" checkout --quiet "$REV_AVANT"; then
        log_error "Le retour arrière a échoué : impossible de restaurer ${REV_AVANT} dans ${DEPOT}."
        exit 1
    fi
    log_info "Code restauré au commit ${REV_AVANT}"

    if compose up -d --remove-orphans; then
        log_ok "Pile relancée sur la version précédente"
    else
        log_error "La relance sur la version précédente a échoué : intervention manuelle requise."
    fi
    exit 1
}

# --- Attente des contrôles de santé -----------------------------------------
attendre_healthchecks() {
    local limite=$(( $(date +%s) + ATTENTE ))
    local total prets reste nom sante marche
    while :; do
        total=0
        prets=0
        while IFS='|' read -r nom sante marche; do
            if [[ -z "$nom" ]]; then
                continue
            fi
            nom="${nom#/}"
            total=$(( total + 1 ))
            if [[ "$marche" == "true" ]] && { [[ "$sante" == "healthy" ]] || [[ "$sante" == "sans-controle" ]]; }; then
                prets=$(( prets + 1 ))
            else
                log_debug "en attente : ${nom} (santé ${sante}, en marche ${marche})"
            fi
        done < <(etats_conteneurs)

        if (( total > 0 )) && (( prets == total )); then
            log_ok "Tous les conteneurs sont prêts (${prets}/${total})"
            NB_CONTENEURS="$total"
            return 0
        fi

        reste=$(( limite - $(date +%s) ))
        if (( reste <= 0 )); then
            log_error "Délai dépassé : ${prets}/${total} conteneur(s) prêt(s) après ${ATTENTE}s."
            return 1
        fi
        log_info "${prets}/${total} conteneur(s) prêt(s), nouveau contrôle dans ${INTERVALLE_SONDAGE}s (${reste}s restantes)"
        sleep "$INTERVALLE_SONDAGE"
    done
}

# --- Vérification finale -----------------------------------------------------
verifier_pile_active() {
    local total=0 nom sante marche
    while IFS='|' read -r nom sante marche; do
        if [[ -z "$nom" ]]; then
            continue
        fi
        nom="${nom#/}"
        total=$(( total + 1 ))
        if [[ "$marche" != "true" ]]; then
            log_error "Conteneur arrêté : ${nom}"
            return 1
        fi
        log_info "conteneur ${nom} : en marche (santé ${sante})"
    done < <(etats_conteneurs)

    if (( total == 0 )); then
        log_error "Aucun conteneur n'a été créé par la pile ${COMPOSE}."
        return 1
    fi
    NB_CONTENEURS="$total"
    return 0
}

# --- Exécution ---------------------------------------------------------------
log_step "1/6 Vérifications préalables"
log_info "fichier compose : ${COMPOSE}"
log_info "environnement   : ${FICHIER_ENV}"
if [[ -n "$DEPOT" ]]; then
    log_info "dépôt           : ${DEPOT} (branche ${BRANCHE})"
else
    log_info "dépôt           : aucun (--depot absent, retour arrière indisponible)"
fi

PERMS_ENV="$(stat -c '%a' "$FICHIER_ENV")"
case "$PERMS_ENV" in
    600|640|400|440) ;;
    *) log_warn "Droits ${PERMS_ENV} sur ${FICHIER_ENV} : ce fichier contient des secrets, envisagez « chmod 600 »." ;;
esac

if [[ -n "$DEPOT" ]]; then
    REV_AVANT="$(git -C "$DEPOT" rev-parse HEAD 2>/dev/null || true)"
    if [[ -z "$REV_AVANT" ]]; then
        die "Impossible de lire le commit courant du dépôt ${DEPOT}."
    fi
    log_info "commit courant  : ${REV_AVANT}"
fi

if (( DRY_RUN )); then
    log_step "Mode simulation : aucune action ne sera appliquée"
    if [[ -n "$DEPOT" ]]; then
        afficher_plan \
            "git -C ${DEPOT} pull --ff-only origin ${BRANCHE}" \
            "$(printf 'docker compose -f %s --env-file %s pull' "$COMPOSE" "$FICHIER_ENV")" \
            "$(printf 'docker compose -f %s --env-file %s up -d --remove-orphans' "$COMPOSE" "$FICHIER_ENV")" \
            "attente des contrôles de santé (${ATTENTE}s au maximum)" \
            "vérification que les conteneurs tournent"
    else
        afficher_plan \
            "$(printf 'docker compose -f %s --env-file %s pull' "$COMPOSE" "$FICHIER_ENV")" \
            "$(printf 'docker compose -f %s --env-file %s up -d --remove-orphans' "$COMPOSE" "$FICHIER_ENV")" \
            "attente des contrôles de santé (${ATTENTE}s au maximum)" \
            "vérification que les conteneurs tournent"
    fi
    fin_script "Simulation terminée : aucun déploiement effectué"
    exit 0
fi

log_step "2/6 Récupération du code"
if [[ -n "$DEPOT" ]]; then
    if ! lancer git -C "$DEPOT" pull --ff-only origin "$BRANCHE"; then
        echec_deploiement "la mise à jour du dépôt ${DEPOT} a échoué (branche ${BRANCHE})"
    fi
    REV_APRES="$(git -C "$DEPOT" rev-parse HEAD 2>/dev/null || true)"
    if [[ "$REV_APRES" == "$REV_AVANT" ]]; then
        log_info "dépôt déjà à jour (commit ${REV_AVANT})"
    else
        log_info "nouveau commit : ${REV_APRES}"
    fi
else
    log_info "aucun dépôt à mettre à jour (--depot absent)"
fi

log_step "3/6 Récupération des images"
if ! lancer compose pull; then
    echec_deploiement "la récupération des images a échoué (registre injoignable ou authentification requise)"
fi

log_step "4/6 Démarrage de la pile"
if ! lancer compose up -d --remove-orphans; then
    echec_deploiement "« docker compose up » a échoué"
fi

log_step "5/6 Attente des contrôles de santé (${ATTENTE}s au maximum)"
if ! attendre_healthchecks; then
    echec_deploiement "tous les conteneurs ne sont pas devenus sains dans le délai imparti"
fi

log_step "6/6 Vérification de la pile"
if ! verifier_pile_active; then
    echec_deploiement "au moins un conteneur de la pile n'est pas en marche"
fi

printf 'hote=%s compose=%s revision=%s conteneurs=%d resultat=ok\n' \
    "$(hostname)" "$COMPOSE" "${REV_APRES:-local}" "$NB_CONTENEURS"

fin_script "Pile déployée et saine (${NB_CONTENEURS} conteneur(s))"
exit 0
