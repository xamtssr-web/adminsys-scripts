#!/usr/bin/env bash
# =============================================================================
# cert-expiry-check.sh — Surveillance de l'expiration des certificats TLS
# -----------------------------------------------------------------------------
# Contrôle deux sources : les certificats sur disque (PEM/CRT) et les
# certificats présentés par des services distants (HTTPS, LDAPS, IMAPS…).
#
# Pourquoi : un certificat expiré casse un service sans prévenir, souvent un
# dimanche. Chaque jour de préavis gagné est une nuit de sommeil gagnée.
#
# Codes retour : 0 = tous valides | 1 = expire bientôt | 2 = expiré / erreur
#
# Exemples :
#   ./cert-expiry-check.sh --dossier /etc/ssl/mes-certificats --jours 30
#   ./cert-expiry-check.sh --hote exemple.fr:443 --hote ldap.interne:636
#   ./cert-expiry-check.sh --dossier /etc/nginx --json | jq .
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

JOURS_AVERTISSEMENT=30
DOSSIERS=()
HOTES=()
FORMAT="texte"
NB_OK=0; NB_WARN=0; NB_CRIT=0
LIGNES=()

usage() {
    entete_script "Vérifie la date d'expiration des certificats TLS (fichiers et services)."
    cat >&2 <<'EOF'

Usage :
  cert-expiry-check.sh [options]

Options :
      --dossier <chemin>   Dossier contenant des certificats PEM/CRT (répétable)
      --hote <hote:port>   Service TLS distant à interroger (répétable, défaut 443)
      --jours <n>          Seuil d'alerte en jours (défaut : 30)
      --json               Sortie JSON
  -q, --quiet              N'affiche que les alertes
  -h, --help               Affiche cette aide

Exemples :
  cert-expiry-check.sh --dossier /etc/ssl/certs --jours 45
  cert-expiry-check.sh --hote nextcloud.exemple.fr:443 --hote mail.exemple.fr:993
  cert-expiry-check.sh --dossier /etc/pki --json > /var/lib/supervision/certs.json
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --dossier) [[ -n "${2:-}" ]] || die_usage "--dossier exige un chemin"; DOSSIERS+=("$2"); shift 2 ;;
        --hote)    [[ -n "${2:-}" ]] || die_usage "--hote exige hote:port";      HOTES+=("$2"); shift 2 ;;
        --jours)   JOURS_AVERTISSEMENT="${2:?}"; shift 2 ;;
        --json)    FORMAT="json"; shift ;;
        -q|--quiet) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

if (( ${#DOSSIERS[@]} == 0 && ${#HOTES[@]} == 0 )); then
    usage
    die_usage "Indiquez au moins un --dossier ou un --hote."
fi

valider_entier "$JOURS_AVERTISSEMENT" "--jours"
require_cmd openssl
require_cmd date
init_script ""

MAINTENANT="$(date +%s)"

# --- Instrumentation ---------------------------------------------------------
ajouter() {
    local source="$1" statut="$2" jours="$3" sujet="$4" expire_le="$5"
    case "$statut" in
        OK)   (( NB_OK++ ))   || true ;;
        WARN) (( NB_WARN++ )) || true ;;
        CRIT) (( NB_CRIT++ )) || true ;;
    esac
    LIGNES+=("${source}|${statut}|${jours}|${sujet}|${expire_le}")
    if (( ! QUIET )) || [[ "$statut" != "OK" ]]; then
        local couleur="$C_OK"
        [[ "$statut" == "WARN" ]] && couleur="$C_WARN"
        [[ "$statut" == "CRIT" ]] && couleur="$C_ERR"
        printf '  %s%-8s%s %-46s %s (expire le %s)\n' \
            "$couleur" "$statut" "$C_RESET" "$(basename "$source")" \
            "$([[ "$jours" -lt 0 ]] && echo "expiré depuis $(( -jours )) j" || echo "dans ${jours} j")" \
            "$expire_le" >&2
    fi
}

# Calcule le nombre de jours restants à partir d'une date de fin (format openssl)
jours_restants() {
    local date_fin="${1:?}"
    local ts_fin
    ts_fin="$(date -d "$date_fin" +%s 2>/dev/null)" || return 1
    echo $(( (ts_fin - MAINTENANT) / 86400 ))
}

# Évalue un certificat déjà converti en PEM sur stdin
# evalue_cert <source lisible>
evalue_cert() {
    local source="$1" pem="$2"
    local sujet date_fin

    if ! printf '%s' "$pem" | openssl x509 -noout -subject >/dev/null 2>&1; then
        return 2   # pas un certificat : on l'ignore silencieusement
    fi

    sujet="$(printf '%s' "$pem" | openssl x509 -noout -subject 2>/dev/null \
        | sed -E 's/^subject=\s*//; s/CN\s*=\s*([^,]+).*/\1/' | cut -c1-60)"
    date_fin="$(printf '%s' "$pem" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"

    local jours
    if ! jours="$(jours_restants "$date_fin")"; then
        ajouter "$source" "CRIT" 0 "$sujet" "date illisible"
        return 0
    fi

    local statut="OK"
    (( jours <= JOURS_AVERTISSEMENT )) && statut="WARN"
    (( jours < 0 )) && statut="CRIT"
    (( jours <= 7 )) && statut="CRIT"

    ajouter "$source" "$statut" "$jours" "${sujet:-inconnu}" "$date_fin"
    return 0
}

# --- 1. Certificats sur disque ----------------------------------------------
if (( ${#DOSSIERS[@]} > 0 )); then
    log_step "Certificats sur disque"
    for dossier in "${DOSSIERS[@]}"; do
        [[ -d "$dossier" ]] || { log_warn "dossier ignoré (absent) : ${dossier}"; continue; }
        # On cherche les fichiers qui contiennent un bloc de certificat
        while IFS= read -r fichier; do
            if ! pem="$(openssl x509 -in "$fichier" -noout -subject 2>/dev/null)"; then
                continue
            fi
            pem="$(cat "$fichier")"
            evalue_cert "$fichier" "$pem" || true
        done < <(find "$dossier" -maxdepth 3 -type f \
            \( -name '*.pem' -o -name '*.crt' -o -name '*.cert' -o -name '*.cer' \) 2>/dev/null)
    done
fi

# --- 2. Services TLS distants -----------------------------------------------
if (( ${#HOTES[@]} > 0 )); then
    log_step "Certificats présentés par les services"
    for cible in "${HOTES[@]}"; do
        hote="${cible%%:*}"
        port="${cible##*:}"
        [[ "$hote" == "$port" ]] && port=443
        valider_port "$port"

        # Récupère le certificat présenté (le pipe peut échouer : on neutralise set -e)
        pem="$(echo | timeout 10 openssl s_client -servername "$hote" -connect "${hote}:${port}" 2>/dev/null \
            | openssl x509 2>/dev/null)" || pem=""

        if [[ -z "$pem" ]]; then
            ajouter "${hote}:${port}" "CRIT" 0 "connexion impossible" "n/a"
            continue
        fi
        evalue_cert "${hote}:${port}" "$pem" || true
    done
fi

# --- Sortie ------------------------------------------------------------------
if [[ "$FORMAT" == "json" ]]; then
    printf '{\n  "date": "%s",\n  "seuil_jours": %d,\n  "resume": {"ok": %d, "avertissement": %d, "critique": %d},\n  "certificats": [\n' \
        "$(date --iso-8601=seconds)" "$JOURS_AVERTISSEMENT" "$NB_OK" "$NB_WARN" "$NB_CRIT"
    premier=1
    for ligne in "${LIGNES[@]}"; do
        IFS='|' read -r src statut jours sujet expire <<< "$ligne"
        (( premier )) || printf ',\n'
        premier=0
        printf '    {"source": "%s", "statut": "%s", "jours_restants": %s, "sujet": "%s", "expire_le": "%s"}' \
            "$src" "$statut" "$jours" "$sujet" "$expire"
    done
    printf '\n  ]\n}\n'
else
    printf '\n%sRésumé : %d valide(s), %d bientôt expiré(s), %d expiré(s)/erreur(s)%s\n' \
        "$C_INFO" "$NB_OK" "$NB_WARN" "$NB_CRIT" "$C_RESET" >&2
fi

if (( NB_CRIT > 0 )); then exit 2; fi
if (( NB_WARN > 0 )); then exit 1; fi
exit 0
