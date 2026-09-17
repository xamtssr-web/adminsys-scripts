#!/usr/bin/env bash
# =============================================================================
# health-check.sh — Contrôle de santé système pour supervision légère
# -----------------------------------------------------------------------------
# Vérifie CPU, mémoire, disques, charge, services systemd, conteneurs Docker
# et points de terminaison HTTP. Sortie lisible par un humain, ou JSON pour
# être consommée par un outil de supervision (Zabbix, Prometheus textfile,
# Nagios, tâche planifiée…).
#
# Pourquoi : avant de déployer une usine à gaz de supervision, un script qui
# sort en code retour 0/1/2 couvre 80 % des besoins et s'intègre partout.
#
# Codes retour :
#   0 = OK     1 = AVERTISSEMENT      2 = CRITIQUE      3 = erreur d'exécution
#
# Exemples :
#   ./health-check.sh
#   ./health-check.sh --json | jq '.checks[] | select(.status!="OK")'
#   ./health-check.sh --seuil-disque 85 --seuil-memoire 90
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# --- Valeurs par défaut ------------------------------------------------------
SEUIL_CPU_W=80;   SEUIL_CPU_C=95
SEUIL_MEM_W=85;   SEUIL_MEM_C=95
SEUIL_DISQUE_W=80; SEUIL_DISQUE_C=90
SEUIL_CHARGE_W=0; SEUIL_CHARGE_C=0      # 0 = calculé depuis le nombre de CPU
FORMAT="texte"
SERVICES=()
CONTENEURS=()
ENDPOINTS=()
CHEMINS=()

# Compteurs de sévérité
NB_OK=0; NB_WARN=0; NB_CRIT=0
RESULTATS=()

usage() {
    entete_script "Contrôle de santé système (CPU, RAM, disques, services, HTTP)."
    cat >&2 <<'EOF'

Usage :
  health-check.sh [options]

Options :
      --seuil-disque <pourcent>     Alerte disque (défaut : 80 / critique 90)
      --seuil-memoire <pourcent>    Alerte mémoire (défaut : 85 / critique 95)
      --seuil-cpu <pourcent>        Alerte CPU (défaut : 80 / critique 95)
      --charge <avert:critique>     Seuils de charge (défaut : 2× et 5× les CPU)
      --service <nom>               Service systemd à vérifier (répétable)
      --conteneur <nom>             Conteneur Docker à vérifier (répétable)
      --http <url>                  URL à tester (répétable)
      --chemin <chemin>             Chemin dont on teste l'écriture (répétable)
      --json                        Sortie JSON (pour supervision)
  -q, --quiet                       N'affiche que les problèmes
  -h, --help                        Affiche cette aide

Exemples :
  health-check.sh --service nginx --service sshd --http https://exemple.fr
  health-check.sh --json --seuil-disque 75 | jq .
  health-check.sh --chemin /var/lib/pgsql --conteneur db
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --seuil-disque)   SEUIL_DISQUE_W="${2:?}"; SEUIL_DISQUE_C="$(( SEUIL_DISQUE_W + 10 ))"; shift 2 ;;
        --seuil-memoire)  SEUIL_MEM_W="${2:?}";    SEUIL_MEM_C="$(( SEUIL_MEM_W + 10 ))";    shift 2 ;;
        --seuil-cpu)      SEUIL_CPU_W="${2:?}";    SEUIL_CPU_C="$(( SEUIL_CPU_W + 15 ))";    shift 2 ;;
        --charge)         SEUIL_CHARGE_W="${2%%:*}"; SEUIL_CHARGE_C="${2##*:}"; shift 2 ;;
        --service)        SERVICES+=("$2"); shift 2 ;;
        --conteneur)      CONTENEURS+=("$2"); shift 2 ;;
        --http)           ENDPOINTS+=("$2"); shift 2 ;;
        --chemin)         CHEMINS+=("$2"); shift 2 ;;
        --json)           FORMAT="json"; shift ;;
        -q|--quiet)       QUIET=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

for seuil in "$SEUIL_DISQUE_W" "$SEUIL_MEM_W" "$SEUIL_CPU_W"; do
    valider_entier "$seuil" "seuil"
    (( seuil <= 100 )) || die_usage "Un seuil en pourcentage ne peut pas dépasser 100."
done

init_script "" ""

# --- Instrumentation ---------------------------------------------------------
# Enregistre un résultat et met à jour les compteurs
# ajouter <nom> <statut OK|WARN|CRIT> <valeur> <detail>
ajouter() {
    local nom="$1" statut="$2" valeur="$3" detail="$4"
    case "$statut" in
        OK)   (( NB_OK++ ))   || true ;;
        WARN) (( NB_WARN++ )) || true ;;
        CRIT) (( NB_CRIT++ )) || true ;;
    esac
    RESULTATS+=("${nom}|${statut}|${valeur}|${detail}")
    if [[ "$FORMAT" == "texte" ]] && { (( ! QUIET )) || [[ "$statut" != "OK" ]]; }; then
        local couleur="$C_OK" symbole="OK"
        [[ "$statut" == "WARN" ]] && { couleur="$C_WARN"; symbole="ATTENTION"; }
        [[ "$statut" == "CRIT" ]] && { couleur="$C_ERR";  symbole="CRITIQUE"; }
        printf '  %s%-11s%s %-22s %s\n' "$couleur" "$symbole" "$C_RESET" "$nom" "$detail" >&2
    fi
}

# --- 1. Charge et taux d'occupation CPU --------------------------------------
log_step "Charge et CPU"
NB_CPU="$(nproc)"
CHARGE_1="$(awk '{print $1}' /proc/loadavg)"
if (( SEUIL_CHARGE_W == 0 )); then
    SEUIL_CHARGE_W="$(awk -v c="$NB_CPU" 'BEGIN{printf "%d", c*2}')"
    SEUIL_CHARGE_C="$(awk -v c="$NB_CPU" 'BEGIN{printf "%d", c*5}')"
fi

statut="OK"
if awk -v l="$CHARGE_1" -v w="$SEUIL_CHARGE_W" 'BEGIN{exit !(l>w)}'; then
    statut="WARN"
fi
if awk -v l="$CHARGE_1" -v c="$SEUIL_CHARGE_C" 'BEGIN{exit !(l>c)}'; then
    statut="CRIT"
fi
ajouter "charge_1min" "$statut" "$CHARGE_1" \
    "charge ${CHARGE_1} sur ${NB_CPU} CPU (seuil ${SEUIL_CHARGE_W}/${SEUIL_CHARGE_C})"

# Taux d'occupation réel : écart de la ligne « cpu » de /proc/stat sur 1 seconde.
# On préfère mesurer plutôt que lire une moyenne instantanée.
if [[ -r /proc/stat ]]; then
    IFS=' ' read -r total1 idle1 <<< "$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)"
    sleep 1
    IFS=' ' read -r total2 idle2 <<< "$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)"
    CPU_POURCENT="$(awk -v t1="$total1" -v i1="$idle1" -v t2="$total2" -v i2="$idle2" \
        'BEGIN{ d=t2-t1; if (d<=0) {print 0} else {printf "%.0f", 100-(i2-i1)*100/d} }')"

    statut="OK"
    if (( CPU_POURCENT >= SEUIL_CPU_W )); then statut="WARN"; fi
    if (( CPU_POURCENT >= SEUIL_CPU_C )); then statut="CRIT"; fi
    ajouter "cpu" "$statut" "${CPU_POURCENT}%" \
        "occupation ${CPU_POURCENT}% (seuils ${SEUIL_CPU_W}/${SEUIL_CPU_C}%) — mesurée sur 1 s"
fi

# --- 2. Mémoire et swap ------------------------------------------------------
log_step "Mémoire"
if command -v free >/dev/null 2>&1; then
    # IFS explicite : la bibliothèque commune impose IFS=$'\n\t', qui empêcherait
    # la séparation sur les espaces et fausserait toutes les valeurs lues.
    IFS=' ' read -r MEM_TOTAL MEM_UTILISEE MEM_POURCENT <<< "$(free -m | awk '/^Mem:/{printf "%s %s %.0f", $2, $3, ($3/$2)*100}')"
    statut="OK"
    (( MEM_POURCENT >= SEUIL_MEM_W )) && statut="WARN"
    (( MEM_POURCENT >= SEUIL_MEM_C )) && statut="CRIT"
    ajouter "memoire" "$statut" "${MEM_POURCENT}%" \
        "$(human_bytes $(( MEM_UTILISEE * 1024 * 1024 )) ) / $(human_bytes $(( MEM_TOTAL * 1024 * 1024 ))) utilisés (${MEM_POURCENT}%) — seuils ${SEUIL_MEM_W}/${SEUIL_MEM_C}%"

    IFS=' ' read -r SWAP_TOTAL SWAP_UTILISEE <<< "$(free -m | awk '/^Swap:/{print $2, $3}')"
    if (( SWAP_TOTAL > 0 )); then
        SWAP_POURCENT=$(( SWAP_UTILISEE * 100 / SWAP_TOTAL ))
        statut="OK"; (( SWAP_POURCENT >= 50 )) && statut="WARN"; (( SWAP_POURCENT >= 80 )) && statut="CRIT"
        ajouter "swap" "$statut" "${SWAP_POURCENT}%" "swap ${SWAP_UTILISEE} Mio / ${SWAP_TOTAL} Mio (${SWAP_POURCENT}%)"
    fi
else
    ajouter "memoire" "OK" "n/a" "commande free indisponible, contrôle ignoré"
fi

# --- 3. Disques --------------------------------------------------------------
log_step "Systèmes de fichiers"
# Un seul appel df pour tous les systèmes, et filtrage sur la colonne « type »
# (un fuse/tmpfs peut faire échouer « df » et, sous set -e, tuerait le script).
while IFS=' ' read -r pcent taille ipcent fstype point; do
    [[ -z "$point" ]] && continue
    case "$fstype" in
        tmpfs|devtmpfs|overlay|squashfs|ramfs|autofs) continue ;;
        *fuse*) continue ;;
    esac

    pcent="${pcent%\%}"
    ipcent="${ipcent%\%}"
    valider_entier "$pcent" "usage disque"

    statut="OK"
    if (( pcent >= SEUIL_DISQUE_W )); then statut="WARN"; fi
    if (( pcent >= SEUIL_DISQUE_C )); then statut="CRIT"; fi

    detail="${pcent}% de ${taille} sur ${point}"
    # Inodes : un disque peut être plein d'inodes tout en ayant de l'espace
    if [[ "$ipcent" =~ ^[0-9]+$ ]] && (( ipcent >= 90 )); then
        statut="WARN"
        detail="${detail}, inodes à ${ipcent}%"
    fi
    nom_disque="${point//\//_}"
    nom_disque="${nom_disque//__/_}"
    nom_disque="${nom_disque#_}"
    ajouter "disque_${nom_disque:-racine}" "$statut" "${pcent}%" "$detail"
done < <(df -h --output=pcent,size,ipcent,fstype,target 2>/dev/null | tail -n +2)

# --- 4. Services systemd -----------------------------------------------------
if (( ${#SERVICES[@]} > 0 )); then
    log_step "Services systemd"
    require_cmd systemctl
    for svc in "${SERVICES[@]}"; do
        if ! systemctl list-unit-files "${svc}*" >/dev/null 2>&1; then
            ajouter "service_${svc}" "WARN" "absent" "service ${svc} introuvable sur cet hôte"
            continue
        fi
        etat="$(systemctl is-active "$svc" 2>/dev/null || true)"
        actif="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        if [[ "$etat" == "active" ]]; then
            statut="OK"; [[ "$actif" != "enabled" ]] && statut="WARN"
            ajouter "service_${svc}" "$statut" "$etat" "${svc} actif (démarrage : ${actif})"
        elif [[ "$etat" == "inactive" || "$etat" == "failed" ]]; then
            # Un service arrêté dont l'unité est désactivée est rarement une panne
            statut="CRIT"; [[ "$actif" == "disabled" ]] && statut="WARN"
            ajouter "service_${svc}" "$statut" "$etat" "${svc} ${etat} (démarrage : ${actif})"
        else
            ajouter "service_${svc}" "OK" "$etat" "${svc} : ${etat}"
        fi
    done
fi

# --- 5. Conteneurs Docker ----------------------------------------------------
if (( ${#CONTENEURS[@]} > 0 )); then
    log_step "Conteneurs Docker"
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        for ct in "${CONTENEURS[@]}"; do
            ligne="$(docker ps -a --filter "name=^/${ct}$" --format '{{.Status}}' | head -1)"
            if [[ -z "$ligne" ]]; then
                ajouter "conteneur_${ct}" "WARN" "absent" "conteneur ${ct} inexistant"
            elif [[ "$ligne" == Up* ]]; then
                # Détecte les redémarrages en boucle annoncés par Docker
                if [[ "$ligne" == *"Restarting"* ]]; then
                    ajouter "conteneur_${ct}" "CRIT" "restart" "${ct} : ${ligne}"
                else
                    ajouter "conteneur_${ct}" "OK" "up" "${ct} : ${ligne}"
                fi
            else
                ajouter "conteneur_${ct}" "CRIT" "down" "${ct} : ${ligne}"
            fi
        done
    else
        ajouter "docker" "WARN" "n/a" "démon Docker inaccessible, contrôle ignoré"
    fi
fi

# --- 6. Points de terminaison HTTP ------------------------------------------
if (( ${#ENDPOINTS[@]} > 0 )); then
    log_step "Points de terminaison HTTP"
    require_cmd curl
    for url in "${ENDPOINTS[@]}"; do
        code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' -L "$url" 2>/dev/null || echo 000)"
        temps="$(curl -s -o /dev/null -m 10 -w '%{time_total}' -L "$url" 2>/dev/null || echo 0)"
        if [[ "$code" == "000" ]]; then
            ajouter "http_${url}" "CRIT" "injoignable" "${url} : aucune réponse (timeout ou DNS)"
        elif (( code >= 500 )); then
            ajouter "http_${url}" "CRIT" "$code" "${url} : HTTP ${code} en ${temps}s"
        elif (( code >= 400 )); then
            ajouter "http_${url}" "WARN" "$code" "${url} : HTTP ${code} en ${temps}s"
        else
            statut="OK"; awk -v t="$temps" 'BEGIN{exit !(t>3)}' && statut="WARN"
            ajouter "http_${url}" "$statut" "$code" "${url} : HTTP ${code} en ${temps}s"
        fi
    done
fi

# --- 7. Écriture sur disque --------------------------------------------------
if (( ${#CHEMINS[@]} > 0 )); then
    log_step "Test d'écriture"
    for chemin in "${CHEMINS[@]}"; do
        if [[ ! -d "$chemin" ]]; then
            ajouter "ecriture_${chemin}" "WARN" "absent" "${chemin} n'existe pas"
            continue
        fi
        if (( DRY_RUN )); then
            ajouter "ecriture_${chemin}" "OK" "simulation" "${chemin} non testé (mode simulation)"
            continue
        fi
        fichier_test="${chemin}/.test-ecriture-$$"
        if touch "$fichier_test" 2>/dev/null; then
            rm -f "$fichier_test"
            ajouter "ecriture_${chemin}" "OK" "possible" "écriture possible dans ${chemin}"
        else
            ajouter "ecriture_${chemin}" "CRIT" "impossible" "écriture refusée dans ${chemin} (droits ou disque plein)"
        fi
    done
fi

# --- Sortie ------------------------------------------------------------------
if [[ "$FORMAT" == "json" ]]; then
    printf '{\n'
    printf '  "hote": "%s",\n' "$(hostname -f 2>/dev/null || hostname)"
    printf '  "date": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "resume": {"ok": %d, "avertissement": %d, "critique": %d},\n' "$NB_OK" "$NB_WARN" "$NB_CRIT"
    printf '  "checks": [\n'
    premier=1
    for res in "${RESULTATS[@]}"; do
        IFS='|' read -r nom statut valeur detail <<< "$res"
        (( premier )) || printf ',\n'
        premier=0
        printf '    {"nom": "%s", "statut": "%s", "valeur": "%s", "detail": "%s"}' \
            "$nom" "$statut" "$valeur" "${detail//\"/\\\"}"
    done
    printf '\n  ]\n}\n'
else
    printf '\n%sRésumé : %d OK, %d avertissement(s), %d critique(s)%s\n' \
        "$C_INFO" "$NB_OK" "$NB_WARN" "$NB_CRIT" "$C_RESET" >&2
fi

if (( NB_CRIT > 0 )); then exit 2; fi
if (( NB_WARN > 0 )); then exit 1; fi
exit 0
