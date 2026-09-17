#!/usr/bin/env bash
# =============================================================================
# test-backup-restore.sh — Test réel de restauration d'une sauvegarde (RTO)
# -----------------------------------------------------------------------------
# Restaure une sauvegarde dans un répertoire temporaire isolé, contrôle
# l'intégrité de l'archive, compare le nombre de fichiers restaurés à
# l'inventaire annoncé, vérifie les empreintes SHA-256 d'un manifeste ainsi que
# la présence de fichiers clés, puis chronomètre l'opération : c'est le RTO
# (temps de reprise) réellement constaté, pas celui du cahier des charges.
#
# Deux modes :
#   --archive <fichier>    archive de sauvegarde (.tar, .tar.gz, .tgz, .tar.bz2,
#                          .tar.xz, .tar.zst, .zip)
#   --source <répertoire>  copie de type rsync : la restauration consiste à
#                          recopier l'arborescence (rsync, sinon cp -a)
#
# Pourquoi : tout le monde a des sauvegardes, presque personne ne les teste.
# Une archive tronquée ou un manifeste incohérent ne se découvre qu'au moment
# de la restauration, c'est-à-dire au pire moment. Ce script exécute la vraie
# restauration — sur un répertoire temporaire, jamais sur le système — et sort
# en échec si la sauvegarde n'est pas restaurable.
#
# Le système n'est jamais modifié : le script ne fait que lire la sauvegarde et
# écrire dans un répertoire temporaire supprimé en fin d'exécution, même en cas
# d'échec.
#
# Codes retour :
#   0  sauvegarde restaurée, toutes les vérifications passées, RTO sous le seuil
#   1  restauration réussie mais avertissement (RTO dépassé, écart de comptage,
#      sauvegarde vide) ou erreur d'exécution
#   2  sauvegarde NON restaurable (point critique) ou paramètres invalides
#
# Exemples :
#   ./test-backup-restore.sh --archive /srv/backup/sauvegarde_2026-09-17.tar.gz
#   ./test-backup-restore.sh -a base.tar.zst --rto-max 300 --fichier-attendu etc/passwd
#   ./test-backup-restore.sh -a base.tar.gz -m base.manifeste --garder
#   ./test-backup-restore.sh --source /mnt/copie/etc --json | jq .rto.secondes
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Les nombres doivent se formater avec un point décimal (JSON, seuils), jamais
# avec une virgule : la locale de l'opérateur ne doit pas casser la supervision.
export LC_NUMERIC=C

# --- Valeurs par défaut ------------------------------------------------------
ARCHIVE=""
SOURCE=""
MANIFESTE=""
ATTENDUS=()                 # chemins devant exister après restauration
FICHIERS_ATTENDUS=0         # 0 = on se fie à l'inventaire de la sauvegarde
RTO_MAX=0                   # 0 = pas de seuil d'alerte
GARDER=0
FORMAT="texte"

FORMAT_ARCHIVE=""           # tar | zip | copie
COMPRESSION=""              # gzip | bzip2 | xz | zstd | aucune
TAR_LECTURE=()              # options à passer à tar pour lire l'archive
OUTIL_COMPRESSION=""
ETAT_COMPRESSION=""

ZONE_TRAVAIL=""
RESTAURATION=""
FICHIER_ERREURS=""

INVENTAIRE=0
NB_FICHIERS_RESTAURES=0
FICHIERS_ANNONCES_EFFECTIF=0
OCTETS_RESTAURES=0
DUREE_MS=0
RTO="0.000"
DEBIT="n/a"
EXTRAIT=0
ETAT_RESTAURABLE="non"
RTO_DEPASSE="non"

MANIFESTE_SHA=""
MANIFESTE_EMPREINTES=()
MANIFESTE_CHEMINS=()
MANIFESTE_FICHIERS=0

HOTE=""
NB_OK=0
NB_WARN=0
NB_CRIT=0
RESULTATS=()

usage() {
    entete_script "Test réel de restauration d'une sauvegarde, avec mesure du RTO."
    cat >&2 <<'EOF'

Usage :
  test-backup-restore.sh --archive <fichier> [options]
  test-backup-restore.sh --source <répertoire> [options]

Sauvegarde à tester (l'un ou l'autre, obligatoire) :
  -a, --archive <fichier>        Archive .tar, .tar.gz, .tgz, .tar.bz2, .tbz2,
                                 .tar.xz, .txz, .tar.zst, .tzst ou .zip
  -s, --source <répertoire>      Copie de type rsync (recopie par rsync, ou par
                                 cp -a si rsync est absent)

Vérifications :
  -m, --manifeste <fichier>      Manifeste SHA-256. Lignes reconnues :
                                   sha256=<empreinte>     empreinte de l'archive
                                   <empreinte>  <chemin>  empreinte d'un fichier
                                 (format sha256sum) ; les autres lignes
                                 (date=, hote=, taille=…) sont ignorées
      --fichier-attendu <chemin> Chemin devant exister après restauration,
                                 relatif à la racine restaurée (répétable)
      --fichiers-attendus <n>    Nombre de fichiers attendu
                                 (défaut : inventaire de l'archive ou de la copie)

Mesure et comportement :
      --rto-max <secondes>       Seuil d'alerte du temps de restauration (RTO)
  -k, --garder                   Conserve le répertoire restauré pour inspection
                                 (défaut : suppression systématique, même en échec)
  -n, --dry-run                  Contrôle la sauvegarde sans rien restaurer :
                                 ni extraction, ni mesure de RTO
      --json                     Sortie JSON sur stdout (pour supervision)
  -q, --quiet                    N'affiche que les avertissements et erreurs
  -v, --verbose                  Affiche les commandes exécutées
  -h, --help                     Affiche cette aide

Codes retour :
  0  sauvegarde restaurée, toutes les vérifications passées, RTO sous le seuil
  1  restauration réussie avec avertissement, ou erreur d'exécution
  2  sauvegarde non restaurable (point critique) ou paramètres invalides

Exemples :
  test-backup-restore.sh --archive /srv/backup/sauvegarde_2026-09-17.tar.gz
  test-backup-restore.sh -a /srv/backup/base.tar.zst --rto-max 300
  test-backup-restore.sh -a base.tar.gz -m base.manifeste --fichier-attendu etc/passwd
  test-backup-restore.sh --source /mnt/copie/etc --rto-max 120 --json
EOF
}

# --- Arguments ---------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        -a|--archive)        [[ -n "${2:-}" ]] || die_usage "-a exige un fichier"; ARCHIVE="$2"; shift 2 ;;
        -s|--source)         [[ -n "${2:-}" ]] || die_usage "-s exige un répertoire"; SOURCE="$2"; shift 2 ;;
        -m|--manifeste)      [[ -n "${2:-}" ]] || die_usage "-m exige un fichier"; MANIFESTE="$2"; shift 2 ;;
        --fichier-attendu)   [[ -n "${2:-}" ]] || die_usage "--fichier-attendu exige un chemin"; ATTENDUS+=("$2"); shift 2 ;;
        --fichiers-attendus) [[ -n "${2:-}" ]] || die_usage "--fichiers-attendus exige un nombre"; FICHIERS_ATTENDUS="$2"; shift 2 ;;
        --rto-max)           [[ -n "${2:-}" ]] || die_usage "--rto-max exige une durée en secondes"; RTO_MAX="$2"; shift 2 ;;
        -k|--garder)         GARDER=1; shift ;;
        -n|--dry-run)        DRY_RUN=1; shift ;;
        --json)              FORMAT="json"; shift ;;
        -q|--quiet)          QUIET=1; shift ;;
        -v|--verbose)        VERBOSE=1; shift ;;
        -h|--help)           usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

# --- Validation des paramètres ----------------------------------------------
if [[ -n "$ARCHIVE" && -n "$SOURCE" ]]; then
    die_usage "--archive et --source sont exclusifs : choisissez une seule sauvegarde à tester."
fi
if [[ -z "$ARCHIVE" && -z "$SOURCE" ]]; then
    usage
    die_usage "Indiquez la sauvegarde à tester : --archive <fichier> ou --source <répertoire>."
fi
if [[ -n "$ARCHIVE" && ! -f "$ARCHIVE" ]]; then
    die_usage "Archive introuvable : ${ARCHIVE}"
fi
if [[ -n "$SOURCE" && ! -d "$SOURCE" ]]; then
    die_usage "Répertoire source introuvable : ${SOURCE}"
fi
if [[ -n "$MANIFESTE" && ! -r "$MANIFESTE" ]]; then
    die_usage "Manifeste illisible : ${MANIFESTE}"
fi
if [[ ! "$RTO_MAX" =~ ^[0-9]+$ ]]; then
    die_usage "--rto-max doit être un nombre entier de secondes (reçu : ${RTO_MAX})"
fi
if [[ ! "$FICHIERS_ATTENDUS" =~ ^[0-9]+$ ]]; then
    die_usage "--fichiers-attendus doit être un nombre entier (reçu : ${FICHIERS_ATTENDUS})"
fi

# --- Fonctions ---------------------------------------------------------------
# Déduit le format et la compression de l'extension de l'archive
detecter_format() {
    local bas="${ARCHIVE,,}"      # comparaison d'extension insensible à la casse
    case "$bas" in
        *.tar.gz|*.tgz)
            FORMAT_ARCHIVE="tar"; COMPRESSION="gzip"; TAR_LECTURE=(-z) ;;
        *.tar.bz2|*.tbz2)
            FORMAT_ARCHIVE="tar"; COMPRESSION="bzip2"; TAR_LECTURE=(-j) ;;
        *.tar.xz|*.txz)
            FORMAT_ARCHIVE="tar"; COMPRESSION="xz"; TAR_LECTURE=(-J) ;;
        *.tar.zst|*.tzst)
            FORMAT_ARCHIVE="tar"; COMPRESSION="zstd"; TAR_LECTURE=(--zstd)
            require_cmd zstd ;;
        *.tar)
            FORMAT_ARCHIVE="tar"; COMPRESSION="aucune"; TAR_LECTURE=() ;;
        *.zip)
            FORMAT_ARCHIVE="zip"; COMPRESSION="aucune"; TAR_LECTURE=()
            require_cmd unzip ;;
        *)
            die_usage "Format non reconnu : ${ARCHIVE} (attendu : .tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz, .txz, .tar.zst, .tzst, .zip)" ;;
    esac
}

# Contrôle le flux compressé (CRC gzip/bzip2/xz/zstd, ou CRC zip).
# Renseigne OUTIL_COMPRESSION ; ETAT_COMPRESSION = ok, absent, echec, sans_objet
controle_compression() {
    ETAT_COMPRESSION="sans_objet"
    case "$COMPRESSION" in
        gzip)  OUTIL_COMPRESSION="gzip" ;;
        bzip2) OUTIL_COMPRESSION="bzip2" ;;
        xz)    OUTIL_COMPRESSION="xz" ;;
        zstd)  OUTIL_COMPRESSION="zstd" ;;
        *)     OUTIL_COMPRESSION="" ;;
    esac

    if [[ "$FORMAT_ARCHIVE" == "zip" ]]; then
        ETAT_COMPRESSION="ok"
        if ! unzip -tqq "$ARCHIVE" >/dev/null 2>&1; then
            ETAT_COMPRESSION="echec"
        fi
    elif [[ -n "$OUTIL_COMPRESSION" ]]; then
        ETAT_COMPRESSION="ok"
        if ! command -v "$OUTIL_COMPRESSION" >/dev/null 2>&1; then
            ETAT_COMPRESSION="absent"
        elif ! "$OUTIL_COMPRESSION" -t "$ARCHIVE" >/dev/null 2>&1; then
            ETAT_COMPRESSION="echec"
        fi
    fi
}

# Inventorie la sauvegarde sans rien extraire : imprime le nombre d'entrées qui
# ne sont pas des répertoires (fichiers, liens, nœuds de périphérique)
inventorier_archive() {
    local total="0"
    if [[ "$FORMAT_ARCHIVE" == "zip" ]]; then
        total="$(unzip -Z1 "$ARCHIVE" 2>/dev/null | awk '!/\/$/ {n++} END {print n+0}' || true)"
    else
        total="$(tar "${TAR_LECTURE[@]}" -tvf "$ARCHIVE" 2>/dev/null | awk '$1 !~ /^d/ {n++} END {print n+0}' || true)"
    fi
    printf '%s' "$total"
}

# Compte les entrées non répertoire d'une arborescence
compter_fichiers() {
    find "$1" ! -type d -printf 'x\n' 2>/dev/null | awk 'END {print NR+0}' || true
}

# Résout un chemin attendu dans l'arborescence restaurée : d'abord le chemin
# exact relatif à la racine restaurée, sinon une recherche par suffixe, car une
# archive contient souvent un répertoire racine en tête (etc/ssh/…).
resoudre_chemin() {
    local recherche="$1" candidat=""
    recherche="${recherche#./}"
    recherche="${recherche#/}"

    candidat="${RESTAURATION}/${recherche}"
    if [[ -e "$candidat" || -L "$candidat" ]]; then
        printf '%s' "$candidat"
        return 0
    fi

    candidat="$(find "$RESTAURATION" -path "*/${recherche}" -print -quit 2>/dev/null || true)"
    if [[ -n "$candidat" ]]; then
        printf '%s' "$candidat"
        return 0
    fi
    return 1
}

sha256_de() {
    sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
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
    local nom statut detail ligne premier=1
    local bool_restaurable="false" bool_rto="false" bool_simulation="false"

    if [[ "$ETAT_RESTAURABLE" == "oui" ]]; then bool_restaurable="true"; fi
    if [[ "$RTO_DEPASSE" == "oui" ]]; then bool_rto="true"; fi
    if (( DRY_RUN )); then bool_simulation="true"; fi

    printf '{\n'
    printf '  "hote": "%s",\n' "$(echapper_json "$HOTE")"
    printf '  "date": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "mode": "%s",\n' "$FORMAT_ARCHIVE"
    if [[ -n "$ARCHIVE" ]]; then
        printf '  "archive": "%s",\n' "$(echapper_json "$ARCHIVE")"
    else
        printf '  "source": "%s",\n' "$(echapper_json "$SOURCE")"
    fi
    printf '  "simulation": %s,\n' "$bool_simulation"
    printf '  "restaurable": %s,\n' "$bool_restaurable"
    printf '  "restauration": {\n'
    printf '    "fichiers_restaures": %d,\n' "$NB_FICHIERS_RESTAURES"
    printf '    "fichiers_annonces": %d,\n' "$FICHIERS_ANNONCES_EFFECTIF"
    printf '    "octets_restaures": %d,\n' "$OCTETS_RESTAURES"
    printf '    "repertoire": "%s"\n' "$(echapper_json "${RESTAURATION:-non_cree}")"
    printf '  },\n'
    printf '  "rto": {"secondes": %s, "seuil_secondes": %d, "depasse": %s, "debit": "%s"},\n' \
        "$RTO" "$RTO_MAX" "$bool_rto" "$(echapper_json "$DEBIT")"
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

    printf '\n%sRésumé : %d OK, %d avertissement(s), %d critique(s)%s\n' \
        "$C_INFO" "$NB_OK" "$NB_WARN" "$NB_CRIT" "$C_RESET" >&2
    if (( DRY_RUN )); then
        printf '%sRTO : non mesuré (mode simulation)%s\n' "$C_DIM" "$C_RESET" >&2
    elif [[ "$ETAT_RESTAURABLE" == "oui" ]]; then
        printf '%sRTO constaté : %s s pour %d fichier(s), %s restaurés (%s)%s\n' \
            "$C_INFO" "$RTO" "$NB_FICHIERS_RESTAURES" "$(human_bytes "$OCTETS_RESTAURES")" "$DEBIT" "$C_RESET" >&2
    else
        printf '%sRTO : aucune restauration exploitable, durée non significative%s\n' "$C_ERR" "$C_RESET" >&2
    fi
    if (( GARDER )) && [[ -n "$RESTAURATION" && -d "$RESTAURATION" ]]; then
        printf '%sRestauration conservée : %s%s\n' "$C_DIM" "$RESTAURATION" "$C_RESET" >&2
    fi
}

terminer() {
    emettre_sortie
    if (( NB_CRIT > 0 )); then exit 2; fi
    if (( NB_WARN > 0 )); then exit 1; fi
    exit 0
}

# Nettoyage : le répertoire temporaire disparaît toujours, sauf --garder, et le
# code retour d'origine est préservé.
# Faux positif de shellcheck : il analyse le corps de la fonction comme un
# gestionnaire de trap (donc jamais appelé directement) et le déclare
# inaccessible.
# shellcheck disable=SC2317
nettoyer() {
    local code=$?
    trap - EXIT
    if (( ! GARDER )) && [[ -n "$ZONE_TRAVAIL" && -d "$ZONE_TRAVAIL" ]]; then
        rm -rf -- "$ZONE_TRAVAIL" || true
    fi
    exit "$code"
}

# --- Démarrage ---------------------------------------------------------------
require_cmd tar awk find sha256sum stat du mktemp
if [[ -n "$ARCHIVE" ]]; then
    detecter_format
else
    FORMAT_ARCHIVE="copie"
fi

init_script "" ""
HOTE="$(hostname -f 2>/dev/null || hostname)"

if [[ -n "$ARCHIVE" ]]; then
    log_info "sauvegarde testée : ${ARCHIVE} ($(human_bytes "$(stat -c %s -- "$ARCHIVE")")) — format ${FORMAT_ARCHIVE}/${COMPRESSION}"
else
    log_info "copie testée : ${SOURCE} ($(human_bytes "$(du -sb -- "$SOURCE" | awk '{print $1}')")) — format ${FORMAT_ARCHIVE}"
fi

ZONE_TRAVAIL="$(mktemp -d "${TMPDIR:-/tmp}/test-restauration-XXXXXXXX")"
RESTAURATION="${ZONE_TRAVAIL}/restauration"
FICHIER_ERREURS="${ZONE_TRAVAIL}/erreurs.txt"
trap 'nettoyer' EXIT
mkdir -p "$RESTAURATION"
log_debug "zone de travail : ${ZONE_TRAVAIL}"

# --- 1/3 Contrôle de la sauvegarde -------------------------------------------
log_step "1/3 Contrôle de la sauvegarde"

if [[ -n "$ARCHIVE" ]]; then
    TAILLE_ARCHIVE="$(stat -c %s -- "$ARCHIVE")"
    if (( TAILLE_ARCHIVE == 0 )); then
        ajouter "archive_non_vide" "CRIT" "archive vide (0 octet) : rien à restaurer"
        terminer
    fi
    ajouter "archive_non_vide" "OK" "$(human_bytes "$TAILLE_ARCHIVE")"

    controle_compression
    case "$ETAT_COMPRESSION" in
        ok)        ajouter "integrite_compression" "OK" "flux ${COMPRESSION} valide (contrôle ${OUTIL_COMPRESSION:-unzip})" ;;
        absent)    ajouter "integrite_compression" "WARN" "outil ${OUTIL_COMPRESSION} absent : CRC non vérifié" ;;
        echec)     ajouter "integrite_compression" "CRIT" "flux ${COMPRESSION} corrompu : archive non restaurable" ;;
        sans_objet) ajouter "integrite_compression" "OK" "archive sans compression : rien à contrôler" ;;
    esac

    INVENTAIRE="$(inventorier_archive)"
    if [[ "$FORMAT_ARCHIVE" == "zip" ]]; then
        if unzip -Z1 "$ARCHIVE" >/dev/null 2>&1; then
            ajouter "integrite_archive" "OK" "index zip lisible"
        else
            ajouter "integrite_archive" "CRIT" "index zip illisible : archive non restaurable"
            terminer
        fi
    else
        if tar "${TAR_LECTURE[@]}" -tf "$ARCHIVE" >/dev/null 2>&1; then
            ajouter "integrite_archive" "OK" "table des matières tar lisible"
        else
            ajouter "integrite_archive" "CRIT" "table des matières tar illisible : archive non restaurable"
            terminer
        fi
    fi
    ajouter "inventaire" "OK" "${INVENTAIRE} fichier(s) annoncé(s) par l'archive"
else
    if [[ -r "$SOURCE" ]]; then
        ajouter "source_lisible" "OK" "copie lisible : ${SOURCE}"
    else
        ajouter "source_lisible" "CRIT" "copie illisible : ${SOURCE}"
        terminer
    fi
    INVENTAIRE="$(compter_fichiers "$SOURCE")"
    ajouter "inventaire" "OK" "${INVENTAIRE} fichier(s) dans la copie source"
fi

if (( FICHIERS_ATTENDUS > 0 )); then
    FICHIERS_ANNONCES_EFFECTIF="$FICHIERS_ATTENDUS"
else
    FICHIERS_ANNONCES_EFFECTIF="$INVENTAIRE"
fi

# --- 2/3 Restauration --------------------------------------------------------
log_step "2/3 Restauration dans un répertoire isolé"
log_info "cible : ${RESTAURATION} (supprimée à la fin, sauf --garder)"

if (( DRY_RUN )); then
    log_info "[simulation] aucune extraction effectuée (mode --dry-run)"
    ajouter "restauration" "OK" "simulation : sauvegarde contrôlée sans extraction"
else
    DEBUT_NS="$(date +%s%N)"
    if [[ "$FORMAT_ARCHIVE" == "zip" ]]; then
        if unzip -qq -o "$ARCHIVE" -d "$RESTAURATION" 2>"$FICHIER_ERREURS"; then
            EXTRAIT=1
        fi
    elif [[ "$FORMAT_ARCHIVE" == "copie" ]]; then
        if command -v rsync >/dev/null 2>&1; then
            log_debug "rsync -a --delete ${SOURCE}/ ${RESTAURATION}/"
            if rsync -a --delete "$SOURCE/" "$RESTAURATION/" 2>"$FICHIER_ERREURS"; then
                EXTRAIT=1
            fi
        else
            log_debug "cp -a ${SOURCE}/. ${RESTAURATION}/"
            if cp -a "$SOURCE/." "$RESTAURATION/" 2>"$FICHIER_ERREURS"; then
                EXTRAIT=1
            fi
        fi
    else
        log_debug "tar ${TAR_LECTURE[*]:-} -xf ${ARCHIVE} -C ${RESTAURATION}"
        if tar "${TAR_LECTURE[@]}" -xf "$ARCHIVE" -C "$RESTAURATION" 2>"$FICHIER_ERREURS"; then
            EXTRAIT=1
        fi
    fi
    FIN_NS="$(date +%s%N)"
    DUREE_MS=$(( (FIN_NS - DEBUT_NS) / 1000000 ))
    RTO="$(awk -v ms="$DUREE_MS" 'BEGIN {printf "%.3f", ms / 1000}')"

    if (( EXTRAIT )); then
        ajouter "restauration" "OK" "restauration effectuée en ${RTO} s"
    else
        ajouter "restauration" "CRIT" "restauration en échec : sauvegarde non restaurable"
        if [[ -s "$FICHIER_ERREURS" ]]; then
            while IFS= read -r ligne_erreur; do
                log_error "  ${ligne_erreur}"
            done < <(head -3 "$FICHIER_ERREURS")
        fi
    fi
fi

# --- 3/3 Vérifications après restauration ------------------------------------
log_step "3/3 Vérifications après restauration"

if (( ! DRY_RUN )) && (( EXTRAIT )); then
    NB_FICHIERS_RESTAURES="$(compter_fichiers "$RESTAURATION")"
    OCTETS_RESTAURES="$(du -sb -- "$RESTAURATION" | awk '{print $1}')"
    if (( DUREE_MS > 0 )); then
        DEBIT="$(awk -v o="$OCTETS_RESTAURES" -v ms="$DUREE_MS" \
            'BEGIN {printf "%.1f Mio/s", (o / 1048576) / (ms / 1000)}')"
    fi

    if (( NB_FICHIERS_RESTAURES == FICHIERS_ANNONCES_EFFECTIF )); then
        ajouter "fichiers_restaures" "OK" "${NB_FICHIERS_RESTAURES} fichier(s) restauré(s) = ${FICHIERS_ANNONCES_EFFECTIF} annoncé(s)"
    elif (( NB_FICHIERS_RESTAURES < FICHIERS_ANNONCES_EFFECTIF )); then
        ajouter "fichiers_restaures" "CRIT" "${NB_FICHIERS_RESTAURES} fichier(s) restauré(s) < ${FICHIERS_ANNONCES_EFFECTIF} annoncé(s) : des fichiers manquent"
    else
        ajouter "fichiers_restaures" "WARN" "${NB_FICHIERS_RESTAURES} fichier(s) restauré(s) > ${FICHIERS_ANNONCES_EFFECTIF} annoncé(s)"
    fi

    if (( OCTETS_RESTAURES > 0 )); then
        ajouter "taille_restauree" "OK" "$(human_bytes "$OCTETS_RESTAURES") restaurés (${DEBIT})"
    else
        ajouter "taille_restauree" "WARN" "restauration vide : la sauvegarde ne contient aucune donnée"
    fi

    ETAT_RESTAURABLE="oui"
else
    ETAT_RESTAURABLE="non"
    ajouter "fichiers_restaures" "OK" "non vérifié (aucune restauration effectuée)"
fi

# Fichiers clés explicitement demandés
for attendu in "${ATTENDUS[@]:-}"; do
    [[ -n "$attendu" ]] || continue
    if (( DRY_RUN )); then
        ajouter "fichier_attendu_${attendu}" "OK" "présence non vérifiée en mode simulation"
    elif resoudre_chemin "$attendu" >/dev/null; then
        trouve="$(resoudre_chemin "$attendu")"
        ajouter "fichier_attendu_${attendu}" "OK" "présent (${trouve#"$RESTAURATION"/})"
    else
        ajouter "fichier_attendu_${attendu}" "CRIT" "ABSENT de la restauration : sauvegarde inexploitable en l'état"
    fi
done

# Manifeste : empreinte de l'archive, puis empreintes des fichiers
if [[ -n "$MANIFESTE" ]]; then
    while IFS= read -r ligne_manifeste; do
        [[ -n "$ligne_manifeste" ]] || continue
        case "$ligne_manifeste" in
            \#*) continue ;;
        esac
        if [[ "$ligne_manifeste" =~ ^sha256=([0-9a-fA-F]{64})$ ]]; then
            MANIFESTE_SHA="${BASH_REMATCH[1]}"
        elif [[ "$ligne_manifeste" =~ ^([0-9a-fA-F]{64})[[:space:]]+\*?(.+)$ ]]; then
            MANIFESTE_EMPREINTES+=("${BASH_REMATCH[1]}")
            MANIFESTE_CHEMINS+=("${BASH_REMATCH[2]}")
        fi
    done < "$MANIFESTE"

    if [[ -n "$MANIFESTE_SHA" ]]; then
        if [[ "$FORMAT_ARCHIVE" == "copie" ]]; then
            ajouter "manifeste_archive" "OK" "empreinte d'archive déclarée : non applicable à un test par copie"
        else
            EMPREINTE_REELLE="$(sha256_de "$ARCHIVE")"
            if [[ "${MANIFESTE_SHA,,}" == "${EMPREINTE_REELLE,,}" ]]; then
                ajouter "manifeste_archive" "OK" "SHA-256 de l'archive conforme au manifeste"
            else
                ajouter "manifeste_archive" "CRIT" "SHA-256 de l'archive différent du manifeste : sauvegarde altérée"
            fi
        fi
    fi

    if (( ${#MANIFESTE_CHEMINS[@]} > 0 )); then
        if (( DRY_RUN )) || (( ! EXTRAIT )); then
            ajouter "manifeste_fichiers" "WARN" "${#MANIFESTE_CHEMINS[@]} empreinte(s) déclarée(s) non vérifiée(s) : aucune restauration"
        else
            NB_CONFORMES=0
            NB_DIVERGENTS=0
            NB_MANQUANTS=0
            for (( i = 0; i < ${#MANIFESTE_CHEMINS[@]}; i++ )); do
                chemin_manifeste="${MANIFESTE_CHEMINS[$i]}"
                if ! cible="$(resoudre_chemin "$chemin_manifeste")"; then
                    log_error "fichier du manifeste absent de la restauration : ${chemin_manifeste}"
                    NB_MANQUANTS=$(( NB_MANQUANTS + 1 ))
                    continue
                fi
                if [[ "${MANIFESTE_EMPREINTES[$i],,}" == "$(sha256_de "$cible")" ]]; then
                    NB_CONFORMES=$(( NB_CONFORMES + 1 ))
                else
                    log_error "empreinte divergente : ${chemin_manifeste}"
                    NB_DIVERGENTS=$(( NB_DIVERGENTS + 1 ))
                fi
                MANIFESTE_FICHIERS=$(( MANIFESTE_FICHIERS + 1 ))
            done
            if (( NB_MANQUANTS > 0 )); then
                ajouter "manifeste_fichiers" "CRIT" "${NB_MANQUANTS} fichier(s) du manifeste absent(s), ${NB_CONFORMES} conforme(s), ${NB_DIVERGENTS} divergent(s)"
            elif (( NB_DIVERGENTS > 0 )); then
                ajouter "manifeste_fichiers" "CRIT" "${NB_DIVERGENTS} empreinte(s) divergente(s) sur ${#MANIFESTE_CHEMINS[@]} : sauvegarde douteuse"
            else
                ajouter "manifeste_fichiers" "OK" "${NB_CONFORMES} empreinte(s) SHA-256 conforme(s)"
            fi
        fi
    elif [[ -z "$MANIFESTE_SHA" ]]; then
        ajouter "manifeste" "WARN" "manifeste fourni mais aucune empreinte SHA-256 exploitable"
    fi
fi

# RTO par rapport au seuil demandé
if (( ! DRY_RUN )) && (( EXTRAIT )); then
    if (( RTO_MAX > 0 )); then
        if (( DUREE_MS > RTO_MAX * 1000 )); then
            RTO_DEPASSE="oui"
            ajouter "rto" "WARN" "${RTO} s > ${RTO_MAX} s : objectif de reprise dépassé"
        else
            ajouter "rto" "OK" "${RTO} s <= ${RTO_MAX} s : objectif de reprise tenu"
        fi
    fi
fi

if (( NB_CRIT > 0 )); then
    fin_script "Test de restauration terminé : sauvegarde NON restaurable"
elif (( NB_WARN > 0 )); then
    fin_script "Test de restauration terminé avec avertissement(s)"
else
    fin_script "Test de restauration terminé"
fi
terminer
