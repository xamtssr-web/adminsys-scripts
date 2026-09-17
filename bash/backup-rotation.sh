#!/usr/bin/env bash
# =============================================================================
# backup-rotation.sh — Sauvegarde avec rotation grand-père/père/fils
# -----------------------------------------------------------------------------
# Crée une archive compressée d'un ou plusieurs répertoires, vérifie son
# intégrité, puis applique une politique de rétention : N archives horaires,
# N quotidiennes, N hebdomadaires et N mensuelles.
#
# Pourquoi : une sauvegarde non vérifiée n'est pas une sauvegarde, et une
# sauvegarde sans rotation finit par saturer le disque — donc par ne plus
# sauvegarder du tout.
#
# Exemples :
#   ./backup-rotation.sh -s /etc -s /home -d /mnt/backup
#   ./backup-rotation.sh -s /var/lib/nextcloud -d /srv/backup --gfs 6-7-4-3
#   ./backup-rotation.sh -s /data -d /srv/backup --dry-run
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

readonly RETENTION_DEFAUT="24-7-4-6"   # horaire-quotidienne-hebdo-mensuelle
readonly PREFIXE="sauvegarde"

usage() {
    entete_script "Sauvegarde des répertoires demandés avec rotation automatique."
    cat >&2 <<'EOF'

Usage :
  backup-rotation.sh -s <répertoire> -d <destination> [options]

Obligatoire :
  -s, --source <chemin>       Répertoire à sauvegarder (répétable)
  -d, --destination <chemin>  Répertoire de destination des archives

Options :
  -g, --gfs <h-q-m-a>         Rétention horaire-quotidienne-hebdo-mensuelle
                              (défaut : 24-7-4-6)
  -c, --chiffrer              Chiffre l'archive avec age (clé publique)
  -k, --cle <fichier>         Clé publique age (requis avec -c)
  -x, --exclure <motif>       Motif à exclure du tar (répétable)
  -n, --dry-run               Simulation : n'écrit rien
  -q, --quiet                 N'affiche que les avertissements et erreurs
  -v, --verbose               Affiche les commandes exécutées
  -h, --help                  Affiche cette aide

Codes retour :
  0  sauvegarde créée et vérifiée
  1  erreur (archive manquante, vérification échouée, espace insuffisant)
  2  mauvaise utilisation (paramètres manquants ou invalides)

Exemples :
  backup-rotation.sh -s /etc -s /root -d /mnt/backup
  backup-rotation.sh -s /var/www -d /srv/backup --gfs 12-7-4-6 -x '*.log'
  backup-rotation.sh -s /data -d /srv/backup -c -k /root/backup-age.pub — chiffrée
EOF
}

# --- Arguments ---------------------------------------------------------------
SOURCES=()
DESTINATION=""
RETENTION="$RETENTION_DEFAUT"
CHIFFRER=0
CLE_AGE=""
EXCLUSIONS=()

while (( $# > 0 )); do
    case "$1" in
        -s|--source)      [[ -n "${2:-}" ]] || die_usage "-s exige un chemin"; SOURCES+=("$2"); shift 2 ;;
        -d|--destination) [[ -n "${2:-}" ]] || die_usage "-d exige un chemin"; DESTINATION="$2"; shift 2 ;;
        -g|--gfs)         [[ -n "${2:-}" ]] || die_usage "-g exige un format h-q-m-a"; RETENTION="$2"; shift 2 ;;
        -c|--chiffrer)    CHIFFRER=1; shift ;;
        -k|--cle)         [[ -n "${2:-}" ]] || die_usage "-k exige un fichier"; CLE_AGE="$2"; shift 2 ;;
        -x|--exclure)     [[ -n "${2:-}" ]] || die_usage "-x exige un motif"; EXCLUSIONS+=("$2"); shift 2 ;;
        -n|--dry-run)     DRY_RUN=1; shift ;;
        -q|--quiet)       QUIET=1; shift ;;
        -v|--verbose)     VERBOSE=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

if (( ${#SOURCES[@]} == 0 )); then usage; die_usage "Au moins une source (-s) est requise."; fi
[[ -n "$DESTINATION" ]] || { usage; die_usage "La destination (-d) est requise."; }

# --- Validation --------------------------------------------------------------
require_cmd tar
require_cmd find
require_cmd awk

if [[ ! "$RETENTION" =~ ^[0-9]+-[0-9]+-[0-9]+-[0-9]+$ ]]; then
    die_usage "--gfs doit respecter le format horaire-quotidienne-hebdo-mensuelle (ex. 24-7-4-6)"
fi
IFS='-' read -r RET_H RET_J RET_S RET_M <<< "$RETENTION"

for src in "${SOURCES[@]}"; do
    [[ -e "$src" ]] || die_usage "Source introuvable : ${src}"
done

if (( CHIFFRER )); then
    require_cmd age
    [[ -n "$CLE_AGE" ]] || die_usage "--chiffrer exige --cle <clé publique age>"
    [[ -r "$CLE_AGE" ]] || die_usage "Clé age illisible : ${CLE_AGE}"
fi

init_script "/var/log/backup-rotation.log" "/var/run/backup-rotation.lock"

# --- Préparation -------------------------------------------------------------
HORODATAGE="$(date '+%Y-%m-%d_%Hh%M')"
NOM_BASE="${PREFIXE}_${HORODATAGE}"
JOUR_SEMAINE="$(date '+%u')"    # 1 = lundi … 7 = dimanche
JOUR_MOIS="$(date '+%d')"

if (( DRY_RUN )); then
    log_info "[simulation] création de ${DESTINATION} si nécessaire"
else
    mkdir -p "$DESTINATION" || die "Impossible de créer ${DESTINATION}"
fi

# Calcul de l'espace nécessaire : on estime à ~60 % de la taille des sources
# (ordre de grandeur d'un tar.gz sur des données mixtes) pour refuser tôt.
TAILLE_TOTALE=0
for src in "${SOURCES[@]}"; do
    taille="$(du -sb "$src" 2>/dev/null | awk '{print $1}')"
    TAILLE_TOTALE=$(( TAILLE_TOTALE + ${taille:-0} ))
done
BESOIN=$(( TAILLE_TOTALE * 6 / 10 ))
DISPONIBLE="$(df -B1 --output=avail "$DESTINATION" | tail -1 | tr -d ' ')"

log_info "sources       : ${SOURCES[*]}"
log_info "taille source : $(human_bytes "$TAILLE_TOTALE")"
log_info "espace libre  : $(human_bytes "$DISPONIBLE") (nécessaire estimé : $(human_bytes "$BESOIN"))"

if (( DISPONIBLE < BESOIN )); then
    die "Espace insuffisant sur ${DESTINATION} : libérez du disque ou réduisez la rétention."
fi

# --- Construction de l'archive ----------------------------------------------
FICHIER_TAR="${DESTINATION}/${NOM_BASE}.tar"
ARCHIVE="${FICHIER_TAR}"

ARGS_TAR=(--create --file "$FICHIER_TAR" --one-file-system)
for motif in "${EXCLUSIONS[@]:-}"; do
    [[ -n "$motif" ]] && ARGS_TAR+=(--exclude="$motif")
done

log_step "1/4 Création de l'archive"
if (( DRY_RUN )); then
    log_info "[simulation] tar ${ARGS_TAR[*]} ${SOURCES[*]}"
else
    tar "${ARGS_TAR[@]}" -- "${SOURCES[@]}" || die "Échec de la création de l'archive"
    log_debug "archive brute : $(du -h "$FICHIER_TAR" | awk '{print $1}')"
fi

log_step "2/4 Compression"
if (( CHIFFRER )); then
    ARCHIVE="${FICHIER_TAR}.age"
    run_sh "gzip -c '${FICHIER_TAR}' | age --encrypt --recipients-file '${CLE_AGE}' -o '${ARCHIVE}'" \
        || die "Échec du chiffrement age"
    run rm -f "$FICHIER_TAR"
else
    ARCHIVE="${FICHIER_TAR}.gz"
    run gzip -9 "$FICHIER_TAR" || die "Échec de la compression"
fi
(( DRY_RUN )) || log_info "archive : ${ARCHIVE} ($(du -h "$ARCHIVE" | awk '{print $1}'))"

log_step "3/4 Vérification d'intégrité"
# Une archive non testée ne vaut rien : on relit le flux complet.
if (( DRY_RUN )); then
    log_info "[simulation] vérification de ${ARCHIVE}"
elif (( CHIFFRER )); then
    # Chiffrée : on ne peut vérifier que la structure age, pas le contenu
    if age --decrypt --identity /dev/null "$ARCHIVE" >/dev/null 2>&1; then
        log_ok "structure age lisible"
    else
        log_warn "vérification complète impossible sans la clé privée age"
    fi
else
    if gzip -t "$ARCHIVE" && tar --list --file="$ARCHIVE" >/dev/null 2>&1; then
        log_ok "archive gzip et tar valides"
    else
        die "Archive corrompue : ${ARCHIVE} — sauvegarde non fiable"
    fi
fi

# --- Manifeste --------------------------------------------------------------
log_step "4/4 Rotation"
MANIFESTE="${DESTINATION}/${NOM_BASE}.manifeste"
if (( ! DRY_RUN )); then
    {
        printf 'date=%s\n' "$(date --iso-8601=seconds)"
        printf 'hote=%s\n' "$(hostname -f 2>/dev/null || hostname)"
        printf 'sources=%s\n' "${SOURCES[*]}"
        printf 'archive=%s\n' "$(basename "$ARCHIVE")"
        printf 'taille=%s\n' "$(stat -c '%s' "$ARCHIVE")"
        printf 'sha256=%s\n' "$(sha256sum "$ARCHIVE" | awk '{print $1}')"
    } > "$MANIFESTE"
    log_ok "manifeste : $(basename "$MANIFESTE")"
fi

# Rotation : on conserve les N dernières de chaque période.
# Les archives horaires : les RET_H plus récentes.
# Les quotidiennes  : celles de 00hxx (ou la première du jour).
# Les hebdo         : celles du dimanche (JOUR_SEMAINE = 7).
# Les mensuelles    : celles du 1er du mois.
supprimer_au_dela() {
    local motif="$1" garder="$2" description="$3"
    local liste total
    mapfile -t liste < <(find "$DESTINATION" -maxdepth 1 -name "${motif}" -type f -printf '%T@ %p\n' \
        | sort -rn | awk '{print $2}')
    total="${#liste[@]}"

    if (( total <= garder )); then
        log_debug "${description} : ${total} archive(s), aucune suppression"
        return 0
    fi

    local i
    for (( i = garder; i < total; i++ )); do
        run rm -f "${liste[$i]}" || true
        log_info "suppression (${description}) : $(basename "${liste[$i]}")"
    done
}

supprimer_au_dela "${PREFIXE}_*.tar.gz" "$RET_H" "horaire"
supprimer_au_dela "${PREFIXE}_*-*-*_00h*.tar.gz" "$RET_J" "quotidienne"
if [[ "$JOUR_SEMAINE" == "7" ]] || (( RET_J == 0 )); then
    supprimer_au_dela "${PREFIXE}_*-*-*_03h*.tar.gz" "$RET_S" "hebdomadaire"
fi
if [[ "$JOUR_MOIS" == "01" ]]; then
    supprimer_au_dela "${PREFIXE}_*-*-*_04h*.tar.gz" "$RET_M" "mensuelle"
fi

# Nettoyage des archives partielles (interruption en cours d'écriture)
if (( ! DRY_RUN )); then
    find "$DESTINATION" -maxdepth 1 -name "${PREFIXE}_*.tar.gz.part" -mtime +1 -delete 2>/dev/null || true
fi

fin_script "Sauvegarde terminée : $(basename "$ARCHIVE")"
