#!/usr/bin/env bash
# =============================================================================
# log-rotate.sh — Rotation et purge des journaux applicatifs
# -----------------------------------------------------------------------------
# Fait ce que fait logrotate, sans dépendre de sa configuration : rotation par
# taille ou quotidienne, compression, rétention et purge des archives anciennes.
#
# Pourquoi : beaucoup d'applications non empaquetées (binaires lancés à la main,
# services maison, conteneurs avec volume) écrivent des journaux que logrotate
# ne surveille pas. Résultat classique : le disque se remplit et le service tombe.
#
# Ce script ne touche pas à un fichier que l'application garde ouvert : il
# renomme puis signale qu'il faut recharger le service (option --reload-service)
# pour que le programme réouvre son descripteur. Sans rechargement, l'application
# continue d'écrire dans l'ancien fichier — c'est la limite de toute rotation
# externe, et ce script le dit explicitement plutôt que de le cacher.
#
# Exemples :
#   ./log-rotate.sh --fichier /var/log/monapp/app.log --max-taille 50M --retention 7
#   ./log-rotate.sh --fichier /var/log/monapp/app.log --reload-service monapp
#   ./log-rotate.sh --fichier /var/log/monapp/app.log --purge-age 30 --dry-run
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

FICHIERS=()
MAX_TAILLE=""
RETENTION=7
PURGE_AGE=""
COMPRESSER=1
RELOAD_SERVICE=""
DEPLACER_COPIE=0
NB_TOURNEES=0
NB_PURGEES=0
NB_ERREURS=0

usage() {
    entete_script "Rotation, compression et purge des journaux applicatifs."
    cat >&2 <<'EOF'

Usage :
  log-rotate.sh --fichier <chemin> [options]

Obligatoire :
      --fichier <chemin>      Journal à traiter (répétable)

Options :
      --max-taille <taille>   Rotation dès que la taille est atteinte
                              (ex. 10M, 500K, 2G). Sans cette option, la
                              rotation est quotidienne (une par jour).
      --retention <n>         Nombre d'archives conservées par journal
                              (défaut : 7)
      --purge-age <jours>     Supprime les archives de plus de N jours
                              (indépendant de --retention)
      --sans-compression      Ne compresse pas les archives (gzip par défaut)
      --copie                 Copie puis tronque au lieu de renommer :
                              indispensable si le programme ne peut pas
                              rouvrir son journal (perte minimale de lignes)
      --reload-service <nom>  Recharge un service systemd après rotation pour
                              qu'il rouvre son descripteur de fichier
  -n, --dry-run               Simulation : n'écrit rien
  -q, --quiet                 N'affiche que les avertissements et erreurs
  -v, --verbose               Affiche le détail des opérations
  -h, --help                  Affiche cette aide

Codes retour :
  0  rotation effectuée (ou rien à faire)
  1  erreur d'exécution (journal absent, compression impossible)
  2  paramètres invalides

Exemples :
  log-rotate.sh --fichier /var/log/monapp/app.log --max-taille 50M
  log-rotate.sh --fichier /var/log/monapp/app.log --retention 14 --purge-age 30
  log-rotate.sh --fichier /var/log/monapp/app.log --copie --reload-service monapp
  log-rotate.sh --fichier /var/log/monapp/app.log --dry-run
EOF
}

# --- Arguments ---------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        --fichier)
            [[ -n "${2:-}" ]] || die_usage "--fichier exige un chemin"
            FICHIERS+=("$2"); shift 2 ;;
        --max-taille)
            [[ -n "${2:-}" ]] || die_usage "--max-taille exige une valeur"
            MAX_TAILLE="$2"; shift 2 ;;
        --retention)
            RETENTION="${2:-}"; shift 2 ;;
        --purge-age)
            PURGE_AGE="${2:-}"; shift 2 ;;
        --sans-compression)
            COMPRESSER=0; shift ;;
        --copie)
            DEPLACER_COPIE=1; shift ;;
        --reload-service)
            [[ -n "${2:-}" ]] || die_usage "--reload-service exige un nom de service"
            RELOAD_SERVICE="$2"; shift 2 ;;
        -n|--dry-run)  DRY_RUN=1; shift ;;
        -q|--quiet)    QUIET=1; shift ;;
        -v|--verbose)  VERBOSE=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

if (( ${#FICHIERS[@]} == 0 )); then
    usage
    die_usage "Indiquez au moins un journal avec --fichier."
fi

valider_entier "$RETENTION" "--retention"
for chemin in "${FICHIERS[@]}"; do
    [[ -e "$chemin" ]] || die "Journal introuvable : ${chemin}"
    [[ -f "$chemin" ]] || die "Ce n'est pas un fichier régulier : ${chemin}"
    [[ -w "$chemin" ]] || die "Journal non accessible en écriture : ${chemin}"
done

if [[ -n "$PURGE_AGE" ]]; then
    valider_entier "$PURGE_AGE" "--purge-age"
fi
if [[ -n "$RELOAD_SERVICE" ]]; then
    require_cmd systemctl
fi
(( COMPRESSER )) && require_cmd gzip
require_cmd stat

init_script "/var/log/log-rotate.log" "/var/run/log-rotate.lock"

# --- Fonctions ---------------------------------------------------------------
# Convertit une taille lisible (10M, 500K, 2G) en octets
taille_en_octets() {
    local valeur="$1" unite nombre
    valeur="${valeur^^}"                       # majuscules
    unite="${valeur: -1}"
    nombre="${valeur%?}"

    case "$unite" in
        K|k) printf '%s' "$(( nombre * 1024 ))" ;;
        M|m) printf '%s' "$(( nombre * 1024 * 1024 ))" ;;
        G|g) printf '%s' "$(( nombre * 1024 * 1024 * 1024 ))" ;;
        [0-9]) printf '%s' "$valeur" ;;        # pas d'unité : octets
        *) die_usage "Taille invalide : $1 (formats acceptés : 500K, 10M, 2G)" ;;
    esac
}

# Taille d'un fichier en octets (0 si absent)
taille_fichier() {
    if [[ -f "$1" ]]; then
        stat -c '%s' "$1"
    else
        printf '0'
    fi
}

# Nom d'archive horodaté, avec suffixe incrémental si le nom est déjà pris
nom_archive() {
    local base="$1" horodatage="$2" candidat suffixe=1
    candidat="${base}.${horodatage}"
    while [[ -e "$candidat" || -e "${candidat}.gz" ]]; do
        candidat="${base}.${horodatage}.${suffixe}"
        suffixe=$(( suffixe + 1 ))
    done
    printf '%s' "$candidat"
}

# --- Traitement --------------------------------------------------------------
for journal in "${FICHIERS[@]}"; do
    taille_avant="$(taille_fichier "$journal")"
    deplacer=0

    if [[ -n "$MAX_TAILLE" ]]; then
        seuil="$(taille_en_octets "$MAX_TAILLE")"
        if (( taille_avant >= seuil )); then
            deplacer=1
            raison="taille $(human_bytes "$taille_avant") ≥ $(human_bytes "$seuil")"
        else
            raison="taille $(human_bytes "$taille_avant") < $(human_bytes "$seuil")"
        fi
    else
        # Mode quotidien : on tourne si aucune archive du jour n'existe encore
        horodatage_du_jour="$(date '+%Y-%m-%d')"
        if compgen -G "${journal}.${horodatage_du_jour}*" >/dev/null; then
            raison="déjà tourné aujourd'hui"
        else
            deplacer=1
            raison="rotation quotidienne"
        fi
    fi

    if (( ! deplacer )); then
        log_info "$(basename "$journal") : rien à faire (${raison})"
        continue
    fi

    log_step "Rotation de ${journal} (${raison})"
    archive="$(nom_archive "$journal" "$(date '+%Y-%m-%d_%Hh%M')")"

    if (( DEPLACER_COPIE )); then
        # Copie puis troncature : le programme garde son descripteur ouvert,
        # on perd au pire les lignes écrites pendant l'opération.
        log_debug "mode copie + troncature (le service peut rouvrir son fichier)"
        run cp --preserve=mode,ownership,timestamps "$journal" "$archive" \
            || { log_error "copie impossible : $journal"; NB_ERREURS=$(( NB_ERREURS + 1 )); continue; }
        run_sh ": > '${journal}'" \
            || { log_error "troncature impossible : $journal"; NB_ERREURS=$(( NB_ERREURS + 1 )); continue; }
    else
        run mv "$journal" "$archive" \
            || { log_error "renommage impossible : $journal"; NB_ERREURS=$(( NB_ERREURS + 1 )); continue; }
        # Le fichier actif doit continuer de recevoir les écritures : on le
        # recrée immédiatement avec les mêmes droits (umask sur l'existant).
        if (( ! DRY_RUN )); then
            touch "$journal"
            chmod --reference="$archive" "$journal" 2>/dev/null || chmod 640 "$journal"
            if command -v chown >/dev/null 2>&1 && [[ "$(stat -c '%u:%g' "$archive")" != "$(stat -c '%u:%g' "$journal")" ]]; then
                chown --reference="$archive" "$journal" 2>/dev/null || true
            fi
        fi
    fi

    # Compression
    if (( COMPRESSER )); then
        if run gzip -9 "$archive"; then
            archive="${archive}.gz"
        else
            log_warn "compression échouée, l'archive reste en clair : ${archive}"
        fi
    fi

    taille_apres="$(taille_fichier "$journal")"
    NB_TOURNEES=$(( NB_TOURNEES + 1 ))
    log_ok "$(basename "$journal") : $(human_bytes "$taille_avant") → $(human_bytes "$taille_apres"), archive $(basename "$archive")"

    # --- Rétention : ne conserver que les N archives les plus récentes ---
    dossier="$(dirname "$journal")"
    nom_base="$(basename "$journal")"
    mapfile -t archives < <(find "$dossier" -maxdepth 1 -type f -name "${nom_base}.*" -printf '%T@ %p\n' \
        | sort -rn | awk '{print $2}')

    if (( ${#archives[@]} > RETENTION )); then
        for (( i = RETENTION; i < ${#archives[@]}; i++ )); do
            run rm -f "${archives[$i]}" || true
            NB_PURGEES=$(( NB_PURGEES + 1 ))
            log_info "rétention : suppression de $(basename "${archives[$i]}")"
        done
    fi

    # --- Purge par ancienneté -------------------------------------------
    if [[ -n "$PURGE_AGE" ]]; then
        while IFS= read -r ancienne; do
            [[ -n "$ancienne" ]] || continue
            run rm -f "$ancienne" || true
            NB_PURGEES=$(( NB_PURGEES + 1 ))
            log_info "purge (>${PURGE_AGE} j) : $(basename "$ancienne")"
        done < <(find "$dossier" -maxdepth 1 -type f -name "${nom_base}.*" -mtime "+${PURGE_AGE}" 2>/dev/null)
    fi

    # --- Rechargement du service ----------------------------------------
    if [[ -n "$RELOAD_SERVICE" ]]; then
        if (( DRY_RUN )); then
            log_info "[simulation] systemctl reload ${RELOAD_SERVICE}"
        elif systemctl reload "$RELOAD_SERVICE" 2>/dev/null; then
            log_debug "service ${RELOAD_SERVICE} rechargé (descripteur rouvert)"
        else
            log_warn "rechargement de ${RELOAD_SERVICE} impossible : vérifiez que le service existe et gère reload"
        fi
    fi
done

# --- Bilan -------------------------------------------------------------------
printf '\n' >&2
log_info "bilan : ${NB_TOURNEES} journal(aux) tourné(s), ${NB_PURGEES} archive(s) supprimée(s)"

if (( NB_ERREURS > 0 )); then
    die "${NB_ERREURS} erreur(s) pendant la rotation"
fi

if (( NB_TOURNEES == 0 )); then
    fin_script "Aucune rotation nécessaire"
else
    fin_script "Rotation terminée"
fi
