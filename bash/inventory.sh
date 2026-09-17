#!/usr/bin/env bash
# =============================================================================
# inventory.sh — Inventaire matériel et logiciel d'un hôte Linux
# -----------------------------------------------------------------------------
# Collecte l'identité de la machine, le système, le matériel, le stockage, le
# réseau, le type de virtualisation et les éléments d'exploitation, puis les
# restitue en texte lisible, en JSON ou en CSV — format directement exploitable
# par un outil d'inventaire (GLPI, OCS, CMDB maison) ou une tâche planifiée.
#
# Pourquoi : renseigner une CMDB à la main est ingrat et périmé dès le
# lendemain. Un inventaire en lecture seule, sans agent ni dépendance (ni jq,
# ni Python), se déploie partout — hôte minimal, conteneur, carte ARM — et se
# relance sans risque pour vérifier que le parc est à jour.
#
# Lecture seule : ce script ne modifie jamais le système. Chaque collecte est
# tolérante à l'échec : une machine sans DMI, sans batterie ou sans interface
# réseau produit un inventaire partiel et un avertissement, jamais un plantage.
#
# Codes retour :
#   0 = inventaire complet
#   1 = inventaire partiel (une donnée essentielle n'a pas pu être collectée)
#   2 = paramètres invalides
#
# Exemples :
#   ./inventory.sh
#   ./inventory.sh --json | jq '.sections.materiel'
#   ./inventory.sh --csv --csv-fichier /var/tmp/parc.csv
#   ./inventory.sh --json --sans-paquets --sans-ports > hote.json
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# --- Valeurs par défaut ------------------------------------------------------
VERSION_SCRIPT="1.0.0"
FORMAT="texte"          # texte | json | csv
CSV_FICHIER=""
SANS_PAQUETS=0
SANS_PORTS=0

# Inventaire collecté : une entrée par ligne, au format « section<TAB>clé<TAB>valeur ».
# La tabulation est utilisée comme séparateur parce que l'IFS global de la
# bibliothèque commune la contient déjà — et jamais dans les valeurs (elles sont
# neutralisées à l'ajout).
RESULTATS=()
NB_INDISPONIBLES=0      # données essentielles absentes -> code retour 1
NB_AVERTISSEMENTS=0     # données secondaires absentes -> simple avertissement

usage() {
    entete_script "Inventaire matériel et logiciel d'un hôte Linux (texte, JSON, CSV)."
    cat >&2 <<'EOF'

Usage :
  inventory.sh [options]

Sortie :
  Par défaut, un inventaire lisible par un humain sur stdout. --json ou --csv
  remplacent cette sortie (si les deux sont donnés, le dernier l'emporte).
  --csv-fichier écrit en plus le CSV dans un fichier.

Options :
      --json                     Sortie JSON sur stdout
      --csv                      Sortie CSV (séparateur virgule) sur stdout
      --csv-fichier <chemin>     Écrit aussi le CSV dans ce fichier
      --sans-paquets             N'inventorie pas les paquets installés (lent)
      --sans-ports               N'inventorie pas les ports en écoute
  -n, --dry-run                  Inventaire rapide : équivaut à
                                 « --sans-paquets --sans-ports »
  -q, --quiet                    N'affiche que les avertissements et erreurs
  -v, --verbose                  Journalise le détail des collectes sur stderr
  -h, --help                     Affiche cette aide

Codes retour :
  0  inventaire complet
  1  inventaire partiel : une donnée essentielle (hôte, système, mémoire ou
     processeur) n'a pas pu être collectée — voir les avertissements
  2  paramètres invalides

Exemples :
  inventory.sh --json | jq '.sections.materiel'
  inventory.sh --csv --csv-fichier /var/tmp/parc.csv
  inventory.sh --json --sans-paquets --sans-ports > hote.json
  inventory.sh --dry-run --verbose

Notes :
  Lecture seule, aucune installation, aucun agent. Aucune dépendance à jq ni à
  Python : le JSON est construit par le script lui-même. Les commandes
  facultatives (lscpu, lsblk, ip, ss, systemctl, dpkg-query, rpm) sont utilisées
  si présentes, avec repli sur /proc, /sys et les fichiers de configuration.
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --json)           FORMAT="json"; shift ;;
        --csv)            FORMAT="csv"; shift ;;
        --csv-fichier)    CSV_FICHIER="${2:?}"; shift 2 ;;
        --sans-paquets)   SANS_PAQUETS=1; shift ;;
        --sans-ports)     SANS_PORTS=1; shift ;;
        -n|--dry-run)     SANS_PAQUETS=1; SANS_PORTS=1; shift ;;
        -q|--quiet)       QUIET=1; shift ;;
        -v|--verbose)     VERBOSE=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

if [[ -n "$CSV_FICHIER" ]]; then
    if [[ -d "$CSV_FICHIER" ]]; then
        die_usage "--csv-fichier attend un fichier, pas un répertoire : ${CSV_FICHIER}"
    fi
    repertoire_csv="$(dirname "$CSV_FICHIER")"
    if [[ ! -d "$repertoire_csv" ]]; then
        die "Répertoire de destination inexistant : ${repertoire_csv}"
    fi
    if [[ ! -w "$repertoire_csv" ]]; then
        die "Répertoire de destination non inscriptible : ${repertoire_csv}"
    fi
fi

init_script "" ""

# -----------------------------------------------------------------------------
# Outils de collecte
# -----------------------------------------------------------------------------

# Lit la première ligne d'un fichier système et renvoie une chaîne vide s'il est
# absent ou illisible — cas normal pour /sys/class/dmi/id sur ARM, en machine
# virtuelle ou en conteneur. Aucun échec ne doit remonter : sous set -e, une
# lecture non protégée ferait sortir le script au milieu de l'inventaire.
lire_fichier() {
    local chemin="$1"
    if [[ -r "$chemin" ]]; then
        head -n 1 "$chemin" 2>/dev/null | tr -d '\n\r\000' || true
    fi
}

# Exécute une commande de lecture et neutralise son échec (commande absente,
# permission refusée, sous-système non monté…).
lire_cmd() {
    "$@" 2>/dev/null || true
}

# Ajoute une entrée d'inventaire : ajouter <section> <clé> <valeur>
ajouter() {
    local section="$1" cle="$2" valeur="${3:-}"
    valeur="${valeur//$'\t'/ }"
    RESULTATS+=("${section}"$'\t'"${cle}"$'\t'"${valeur}")
}

# Comme ajouter, mais note explicitement une valeur absente. important=1 pour
# les données sans lesquelles l'inventaire n'a pas de sens (code retour 1).
ajouter_ou_na() {
    local section="$1" cle="$2" valeur="$3" important="${4:-0}"
    if [[ -z "$valeur" ]]; then
        if (( important )); then
            (( NB_INDISPONIBLES++ )) || true
            log_warn "Donnée essentielle introuvable : ${section}.${cle}"
        else
            NB_AVERTISSEMENTS=$(( NB_AVERTISSEMENTS + 1 ))
            log_debug "Donnée secondaire indisponible : ${section}.${cle}"
        fi
        ajouter "$section" "$cle" "non déterminable"
    else
        ajouter "$section" "$cle" "$valeur"
    fi
}

# Valeur d'une clé de /etc/os-release, sans sourcer le fichier (le sourcer
# écraserait nos variables et exécuterait du code de la distribution).
valeur_os_release() {
    local cle="$1"
    if [[ -r /etc/os-release ]]; then
        awk -F= -v c="$cle" '$1 == c { gsub(/^"|"$/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true
    fi
}

# Type de châssis DMI en clair (codes SMBIOS, table 7.4.1)
libelle_chassis() {
    case "${1:-}" in
        1)  printf 'autre' ;;
        2)  printf 'inconnu' ;;
        3)  printf 'ordinateur de bureau' ;;
        4)  printf 'bureau compact' ;;
        5)  printf 'boîtier pizza' ;;
        6)  printf 'mini-tour' ;;
        7)  printf 'tour' ;;
        8)  printf 'portable' ;;
        9)  printf 'ordinateur portable' ;;
        10) printf 'bloc-notes' ;;
        11) printf 'portable de poche' ;;
        14) printf 'sous-bloc-notes' ;;
        17) printf 'serveur principal' ;;
        23) printf 'châssis en rack' ;;
        28) printf 'châssis lame' ;;
        30) printf 'tablette' ;;
        35) printf 'mini-PC' ;;
        "") printf '' ;;
        *)  printf 'type %s' "$1" ;;
    esac
}

# Durée en secondes -> « 3j 04h 12min »
duree_lisible() {
    local secondes="$1"
    printf '%dj %02dh %02dmin' \
        "$(( secondes / 86400 ))" \
        "$(( (secondes % 86400) / 3600 ))" \
        "$(( (secondes % 3600) / 60 ))"
}

# Extrait la valeur d'un couple « CLE="valeur" » produit par « lsblk -P »
champ_lsblk() {
    local ligne="$1" cle="$2"
    if [[ "$ligne" =~ ${cle}=\"([^\"]*)\" ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

# -----------------------------------------------------------------------------
# 1. Identité de la machine
# -----------------------------------------------------------------------------
log_step "Identité"
HOTE_COURT="$(lire_cmd hostname)"
HOTE_FQDN="$(lire_cmd hostname -f)"
if [[ -z "$HOTE_FQDN" ]]; then
    HOTE_FQDN="$HOTE_COURT"
fi
ajouter_ou_na "identite" "nom_hote" "$HOTE_COURT" 1
ajouter_ou_na "identite" "fqdn" "$HOTE_FQDN"
ajouter "identite" "date_inventaire" "$(date '+%Y-%m-%d %H:%M:%S %Z')"

# Le DMI existe sur PC x86/UEFI ; il est absent de la plupart des cartes ARM et
# des conteneurs, d'où le repli sur l'arbre de périphériques du noyau.
constructeur=""; modele=""; version_materiel=""; numero_serie=""
carte_mere=""; chassis=""; micrologiciel=""; date_micrologiciel=""
if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
    constructeur="$(lire_fichier /sys/class/dmi/id/sys_vendor)"
    modele="$(lire_fichier /sys/class/dmi/id/product_name)"
    version_materiel="$(lire_fichier /sys/class/dmi/id/product_version)"
    numero_serie="$(lire_fichier /sys/class/dmi/id/product_serial)"
    carte_mere="$(lire_fichier /sys/class/dmi/id/board_name)"
    chassis="$(libelle_chassis "$(lire_fichier /sys/class/dmi/id/chassis_type)")"
    micrologiciel="$(lire_fichier /sys/class/dmi/id/bios_version)"
    date_micrologiciel="$(lire_fichier /sys/class/dmi/id/bios_date)"
else
    modele="$(lire_fichier /proc/device-tree/model)"
    numero_serie="$(lire_fichier /sys/firmware/devicetree/base/serial-number)"
    log_warn "DMI absent (ARM, machine virtuelle ou conteneur) : constructeur et modèle lus depuis l'arbre de périphériques du noyau"
fi
ajouter_ou_na "identite" "constructeur" "$constructeur"
ajouter_ou_na "identite" "modele" "$modele"
ajouter_ou_na "identite" "version_materiel" "$version_materiel"
ajouter_ou_na "identite" "numero_serie" "$numero_serie"
ajouter_ou_na "identite" "carte_mere" "$carte_mere"
ajouter_ou_na "identite" "chassis" "$chassis"
ajouter_ou_na "identite" "micrologiciel" "$micrologiciel"
ajouter_ou_na "identite" "date_micrologiciel" "$date_micrologiciel"

# -----------------------------------------------------------------------------
# 2. Système d'exploitation
# -----------------------------------------------------------------------------
log_step "Système"
distribution="$(valeur_os_release PRETTY_NAME)"
version_distribution="$(valeur_os_release VERSION_ID)"
identifiant_distribution="$(valeur_os_release ID)"
noyau="$(lire_cmd uname -r)"
architecture="$(lire_cmd uname -m)"
architecture_paquets="$(lire_cmd dpkg --print-architecture)"

ajouter_ou_na "systeme" "distribution" "$distribution" 1
ajouter_ou_na "systeme" "version_distribution" "$version_distribution"
ajouter_ou_na "systeme" "identifiant_distribution" "$identifiant_distribution"
ajouter_ou_na "systeme" "noyau" "$noyau" 1
ajouter_ou_na "systeme" "architecture" "$architecture" 1
ajouter_ou_na "systeme" "architecture_paquets" "$architecture_paquets"

# Date d'installation : l'horodatage de naissance du système de fichiers racine
# (ou de /var/log/installer) — estimation honnête, pas une valeur exacte : une
# installation par image disque ou par clonage porte la date de création de
# l'image.
date_installation() {
    local horodatage=""
    if [[ -e /var/log/installer ]]; then
        horodatage="$(stat -c '%W' /var/log/installer 2>/dev/null || true)"
    fi
    if [[ -z "$horodatage" || "$horodatage" == "0" ]]; then
        horodatage="$(stat -c '%W' / 2>/dev/null || true)"
    fi
    if [[ -z "$horodatage" || "$horodatage" == "0" ]]; then
        horodatage="$(stat -c '%Y' /etc/hostname 2>/dev/null || true)"
    fi
    if [[ -n "$horodatage" && "$horodatage" != "0" ]]; then
        date -d "@${horodatage}" '+%Y-%m-%d' 2>/dev/null || true
    fi
}
ajouter_ou_na "systeme" "date_installation_estimee" "$(date_installation)"

# -----------------------------------------------------------------------------
# 3. Matériel : processeur et mémoire
# -----------------------------------------------------------------------------
log_step "Matériel"
modele_processeur=""
if command -v lscpu >/dev/null 2>&1; then
    modele_processeur="$(lire_cmd lscpu | awk -F': *' '/^Model name:/ { print $2; exit }')"
fi
if [[ -z "$modele_processeur" && -r /proc/cpuinfo ]]; then
    modele_processeur="$(awk -F': *' '/^(model name|Model|Hardware|Processor)/ { print $2; exit }' /proc/cpuinfo 2>/dev/null || true)"
fi

coeurs_logiques="$(lire_cmd nproc)"
if [[ ! "$coeurs_logiques" =~ ^[0-9]+$ ]]; then
    coeurs_logiques="$(lire_cmd getconf _NPROCESSORS_ONLN)"
fi
if [[ ! "$coeurs_logiques" =~ ^[0-9]+$ && -r /proc/cpuinfo ]]; then
    coeurs_logiques="$(awk '/^processor/ { n++ } END { print n+0 }' /proc/cpuinfo 2>/dev/null || true)"
fi

coeurs_physiques=""
if command -v lscpu >/dev/null 2>&1; then
    coeurs_physiques="$(lire_cmd lscpu | awk -F': *' '
        /^Socket\(s\):/          { sockets = $2 }
        /^Core\(s\) per socket:/ { coeurs = $2 }
        END { if (sockets != "" && coeurs != "") printf "%d", sockets * coeurs }')"
fi
if [[ -z "$coeurs_physiques" && -r /proc/cpuinfo ]]; then
    # Repli : nombre de couples (identifiant physique, identifiant de cœur)
    coeurs_physiques="$(awk -F': *' '
        /^physical id/ { pid = $2 }
        /^core id/     { vus[pid ":" $2] = 1 }
        END { for (c in vus) n++; if (n > 0) printf "%d", n }' /proc/cpuinfo 2>/dev/null || true)"
fi

frequence_processeur=""
if command -v lscpu >/dev/null 2>&1; then
    frequence_processeur="$(lire_cmd lscpu | awk -F': *' '/^CPU max MHz:/ { printf "%.0f MHz", $2; exit }')"
fi
if [[ -z "$frequence_processeur" && -r /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ]]; then
    khz="$(lire_fichier /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)"
    if [[ "$khz" =~ ^[0-9]+$ ]]; then
        frequence_processeur="$(( khz / 1000 )) MHz"
    fi
fi

memoire_kio="$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || true)"
swap_kio="$(awk '/^SwapTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || true)"
memoire_totale=""; swap_total=""; memoire_octets=""
if [[ "$memoire_kio" =~ ^[0-9]+$ ]]; then
    memoire_octets=$(( memoire_kio * 1024 ))
    memoire_totale="$(human_bytes "$memoire_octets")"
fi
if [[ "$swap_kio" =~ ^[0-9]+$ && "$swap_kio" -gt 0 ]]; then
    swap_total="$(human_bytes $(( swap_kio * 1024 )))"
else
    swap_total="aucun"
fi

ajouter_ou_na "materiel" "processeur" "$modele_processeur" 1
ajouter_ou_na "materiel" "coeurs_logiques" "$coeurs_logiques"
ajouter_ou_na "materiel" "coeurs_physiques" "$coeurs_physiques"
ajouter_ou_na "materiel" "frequence_max" "$frequence_processeur"
ajouter_ou_na "materiel" "memoire_totale" "$memoire_totale" 1
ajouter_ou_na "materiel" "memoire_totale_octets" "$memoire_octets"
ajouter "materiel" "swap_total" "$swap_total"

# -----------------------------------------------------------------------------
# 4. Stockage : disques et partitions (taille, modèle, montage, SSD/HDD)
# -----------------------------------------------------------------------------
log_step "Stockage"
nb_disques=0
nb_blocs=0
if command -v lsblk >/dev/null 2>&1; then
    while IFS= read -r ligne; do
        [[ -n "$ligne" ]] || continue
        nom_bloc="$(champ_lsblk "$ligne" NAME)"
        [[ -n "$nom_bloc" ]] || continue
        type_bloc="$(champ_lsblk "$ligne" TYPE)"
        taille_bloc="$(champ_lsblk "$ligne" SIZE)"
        modele_bloc="$(champ_lsblk "$ligne" MODEL)"
        rota_bloc="$(champ_lsblk "$ligne" ROTA)"
        transport_bloc="$(champ_lsblk "$ligne" TRAN)"
        montages_bloc="$(champ_lsblk "$ligne" MOUNTPOINTS)"
        # lsblk -P échappe les caractères non imprimables : un point de montage
        # contenant un saut de ligne arrive sous la forme « \x0a ».
        montages_bloc="${montages_bloc//\\x0a/ }"
        montages_bloc="${montages_bloc//\\n/ }"

        support="inconnu"
        if [[ "$rota_bloc" == "0" ]]; then support="SSD"; fi
        if [[ "$rota_bloc" == "1" ]]; then support="HDD (disque rotatif)"; fi
        [[ -n "$transport_bloc" ]] || transport_bloc="inconnu"
        [[ -n "$montages_bloc" ]] || montages_bloc="non monté"
        [[ -n "$modele_bloc" ]] || modele_bloc="modèle inconnu"

        taille_lisible="$taille_bloc"
        if [[ "$taille_bloc" =~ ^[0-9]+$ ]]; then
            taille_lisible="$(human_bytes "$taille_bloc")"
        fi

        ajouter "stockage" "$nom_bloc" \
            "${type_bloc} | ${taille_lisible} | ${support} | bus ${transport_bloc} | ${modele_bloc} | montage : ${montages_bloc}"
        if [[ "$type_bloc" == "disk" ]]; then
            (( nb_disques++ )) || true
        fi
        (( nb_blocs++ )) || true
    done < <(lsblk -b -n -P -o NAME,TYPE,SIZE,MODEL,ROTA,TRAN,MOUNTPOINTS 2>/dev/null || true)
else
    log_warn "lsblk absent : le détail des disques n'a pas pu être collecté"
fi
ajouter "stockage" "nombre_disques" "$nb_disques"
ajouter "stockage" "nombre_peripheriques_bloc" "$nb_blocs"

# -----------------------------------------------------------------------------
# 5. Réseau : interfaces, adresses, passerelle, DNS
# -----------------------------------------------------------------------------
log_step "Réseau"
ip_disponible=0
if command -v ip >/dev/null 2>&1; then
    ip_disponible=1
else
    log_warn "commande ip absente : adresses réseau partiellement collectées"
fi

nb_interfaces=0
for chemin in /sys/class/net/*; do
    [[ -e "$chemin" ]] || continue
    nom_interface="${chemin##*/}"
    if [[ "$nom_interface" == "lo" ]]; then
        continue
    fi
    adresse_mac="$(lire_fichier "${chemin}/address")"
    etat_interface="$(lire_fichier "${chemin}/operstate")"
    vitesse_interface="$(lire_fichier "${chemin}/speed")"

    adresses_v4=""; adresses_v6=""
    if (( ip_disponible )); then
        adresses_v4="$(lire_cmd ip -4 -o addr show dev "$nom_interface" \
            | awk '{ printf "%s%s", sep, $4; sep = ", " }')"
        adresses_v6="$(lire_cmd ip -6 -o addr show dev "$nom_interface" scope global \
            | awk '{ printf "%s%s", sep, $4; sep = ", " }')"
    fi
    [[ -n "$adresses_v4" ]] || adresses_v4="aucune"
    [[ -n "$adresses_v6" ]] || adresses_v6="aucune"
    [[ -n "$etat_interface" ]] || etat_interface="inconnu"
    [[ -n "$adresse_mac" ]] || adresse_mac="inconnue"

    detail_interface="état ${etat_interface} | MAC ${adresse_mac} | IPv4 ${adresses_v4} | IPv6 ${adresses_v6}"
    if [[ "$vitesse_interface" =~ ^[0-9]+$ ]]; then
        detail_interface="${detail_interface} | ${vitesse_interface} Mb/s"
    fi
    ajouter "reseau" "interface_${nom_interface}" "$detail_interface"
    (( nb_interfaces++ )) || true
done
ajouter "reseau" "nombre_interfaces" "$nb_interfaces"

passerelle=""; passerelle_v6=""
if (( ip_disponible )); then
    passerelle="$(lire_cmd ip -4 route show default | awk '/^default/ { print $3; exit }')"
    passerelle_v6="$(lire_cmd ip -6 route show default | awk '/^default/ { print $3; exit }')"
    # Passerelle déclarée sans route par défaut (interface down au moment de la collecte)
    if [[ -z "$passerelle" && -r /etc/network/interfaces ]]; then
        passerelle="$(awk '$1 == "gateway" { print $2; exit }' /etc/network/interfaces 2>/dev/null || true)"
    fi
fi
ajouter_ou_na "reseau" "passerelle_v4" "$passerelle"
ajouter_ou_na "reseau" "passerelle_v6" "$passerelle_v6"

dns="$(awk '/^[[:space:]]*nameserver/ { printf "%s%s", sep, $2; sep = ", " }' /etc/resolv.conf 2>/dev/null || true)"
domaine_recherche="$(awk '/^[[:space:]]*(search|domain)/ { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)"
ajouter_ou_na "reseau" "serveurs_dns" "$dns"
ajouter_ou_na "reseau" "domaine_recherche" "$domaine_recherche"

# -----------------------------------------------------------------------------
# 6. Virtualisation
# -----------------------------------------------------------------------------
log_step "Virtualisation"
type_virt="$(lire_cmd systemd-detect-virt)"
if [[ -z "$type_virt" ]]; then
    type_virt="$(lire_fichier /sys/class/dmi/id/product_name)"
fi

virtualisation="physique"
if [[ -n "$type_virt" && "$type_virt" != "none" ]]; then
    virtualisation="$type_virt"
fi

conteneur="non"
case "$type_virt" in
    docker|podman|lxc|lxc-libvirt|systemd-nspawn|openvz|rkt|wsl) conteneur="oui (${type_virt})" ;;
esac
if [[ -f /.dockerenv ]]; then
    conteneur="oui (docker)"
fi
if [[ -z "$type_virt" && -r /proc/1/cgroup ]] && grep -qE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; then
    conteneur="oui (détecté via /proc/1/cgroup)"
fi

hyperviseur=""
if [[ -r /sys/class/dmi/id/product_name ]]; then
    case "$(lire_fichier /sys/class/dmi/id/product_name)" in
        *KVM*)              hyperviseur="KVM" ;;
        *VMware*)           hyperviseur="VMware" ;;
        *VirtualBox*)       hyperviseur="VirtualBox" ;;
        *"Microsoft Corporation"*) hyperviseur="Hyper-V" ;;
        *"Standard PC"*)    hyperviseur="QEMU (BIOS standard)" ;;
        *QEMU*)             hyperviseur="QEMU" ;;
        *Xen*)              hyperviseur="Xen" ;;
    esac
fi

ajouter "virtualisation" "type" "$virtualisation"
ajouter "virtualisation" "conteneur" "$conteneur"
ajouter_ou_na "virtualisation" "hyperviseur" "$hyperviseur"
if [[ -r /proc/1/cgroup ]]; then
    ajouter "virtualisation" "cgroup_pid1" "$(head -n 1 /proc/1/cgroup 2>/dev/null | tr -d '\n\r' || true)"
fi

# -----------------------------------------------------------------------------
# 7. Exploitation : uptime, charge, paquets, services, utilisateurs, ports
# -----------------------------------------------------------------------------
log_step "Exploitation"
uptime_secondes="$(awk '{ printf "%d", $1 }' /proc/uptime 2>/dev/null || true)"
if [[ "$uptime_secondes" =~ ^[0-9]+$ ]]; then
    ajouter "exploitation" "demarrage_duree" "$(duree_lisible "$uptime_secondes")"
    demarrage="$(lire_cmd uptime -s)"
    if [[ -z "$demarrage" ]]; then
        demarrage="$(date -d "@$(( $(date +%s) - uptime_secondes ))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
    fi
    ajouter_ou_na "exploitation" "dernier_demarrage" "$demarrage"
fi

charge="$(awk '{ printf "%s %s %s", $1, $2, $3 }' /proc/loadavg 2>/dev/null || true)"
ajouter_ou_na "exploitation" "charge_1_5_15min" "$charge"

# Paquets installés : dpkg puis rpm, sans jamais échouer sur l'absence de l'un
if (( SANS_PAQUETS )); then
    ajouter "exploitation" "paquets_installes" "non collecté (--sans-paquets)"
    ajouter "exploitation" "gestionnaire_paquets" "non collecté (--sans-paquets)"
else
    nb_paquets=""; gestionnaire=""
    if command -v dpkg-query >/dev/null 2>&1; then
        gestionnaire="dpkg"
        # Note : ${db:Status-Abbrev} est une variable de format de dpkg-query,
        # pas une expansion du shell — les quotes simples sont volontaires, et
        # seul l'état « ii » (installé) est compté, pas les paquets désinstallés
        # dont la configuration subsiste.
        # shellcheck disable=SC2016
        nb_paquets="$(lire_cmd dpkg-query -W -f '${db:Status-Abbrev}\n' | grep -c '^ii' || true)"
    elif command -v rpm >/dev/null 2>&1; then
        gestionnaire="rpm"
        nb_paquets="$(lire_cmd rpm -qa | wc -l | tr -d ' ')"
    fi
    if [[ ! "$nb_paquets" =~ ^[0-9]+$ ]] || (( nb_paquets == 0 )); then
        nb_paquets=""
    fi
    ajouter_ou_na "exploitation" "paquets_installes" "$nb_paquets"
    ajouter_ou_na "exploitation" "gestionnaire_paquets" "$gestionnaire"
fi

# Services systemd
services_actifs=""; services_actives=""
if command -v systemctl >/dev/null 2>&1; then
    services_actifs="$(lire_cmd systemctl list-units --type=service --state=running --no-legend --no-pager | wc -l | tr -d ' ')"
    services_actives="$(lire_cmd systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager | wc -l | tr -d ' ')"
fi
ajouter_ou_na "exploitation" "services_actifs" "$services_actifs"
ajouter_ou_na "exploitation" "services_actives_au_demarrage" "$services_actives"

# Comptes disposant d'un shell de connexion (root et comptes utilisateurs)
comptes_shell="$(awk -F: '
    ($3 == 0 || $3 >= 1000) && $7 ~ /(bash|sh|zsh|ksh|csh|tcsh|fish)$/ {
        printf "%s%s(%s)", sep, $1, $3; sep = ", "
    }' /etc/passwd 2>/dev/null || true)"
ajouter_ou_na "exploitation" "comptes_avec_shell" "$comptes_shell"

# Ports en écoute
if (( SANS_PORTS )); then
    ajouter "exploitation" "ports_en_ecoute" "non collecté (--sans-ports)"
    ajouter "exploitation" "nombre_ports_en_ecoute" "non collecté (--sans-ports)"
else
    if command -v ss >/dev/null 2>&1; then
        ports="$(lire_cmd ss -H -tuln | awk '{ print $1, $5 }' | sort -u \
            | awk '{ printf "%s%s/%s", sep, $2, $1; sep = ", " }')"
        nb_ports="$(lire_cmd ss -H -tuln | wc -l | tr -d ' ')"
        ajouter_ou_na "exploitation" "ports_en_ecoute" "$ports"
        ajouter_ou_na "exploitation" "nombre_ports_en_ecoute" "$nb_ports"
    else
        ajouter "exploitation" "ports_en_ecoute" "non déterminable (commande ss absente)"
        NB_AVERTISSEMENTS=$(( NB_AVERTISSEMENTS + 1 ))
    fi
fi

# Fuseau horaire et synchronisation de l'heure
fuseau="$(lire_cmd timedatectl show -p Timezone --value)"
if [[ -z "$fuseau" && -L /etc/localtime ]]; then
    fuseau="$(lire_cmd readlink /etc/localtime)"
    fuseau="${fuseau#*/zoneinfo/}"
fi
if [[ -z "$fuseau" && -r /etc/timezone ]]; then
    fuseau="$(lire_fichier /etc/timezone)"
fi
ajouter_ou_na "exploitation" "fuseau_horaire" "$fuseau"

synchro_ntp="$(lire_cmd timedatectl show -p NTPSynchronized --value)"
service_temps=""
for service in systemd-timesyncd chronyd ntp ntpsec; do
    if command -v systemctl >/dev/null 2>&1; then
        etat_service="$(lire_cmd systemctl is-active "$service")"
        if [[ "$etat_service" == "active" ]]; then
            service_temps="$service"
            break
        fi
    fi
done
if [[ -z "$service_temps" ]]; then
    service_temps="aucun service de synchronisation actif"
fi
if [[ "$synchro_ntp" == "yes" ]]; then
    ajouter "exploitation" "synchronisation_ntp" "synchronisée (${service_temps})"
elif [[ "$synchro_ntp" == "no" ]]; then
    ajouter "exploitation" "synchronisation_ntp" "non synchronisée (${service_temps})"
else
    ajouter_ou_na "exploitation" "synchronisation_ntp" "$service_temps"
fi

# -----------------------------------------------------------------------------
# Sortie — stdout porte les données, stderr les messages
# -----------------------------------------------------------------------------

# Échappe une valeur pour du JSON : sans cela, un modèle de disque contenant un
# guillemet produirait un JSON invalide.
echapper_json() {
    local valeur="$1"
    valeur="${valeur//\\/\\\\}"
    valeur="${valeur//\"/\\\"}"
    valeur="${valeur//$'\n'/\\n}"
    valeur="${valeur//$'\r'/\\r}"
    valeur="${valeur//$'\t'/\\t}"
    printf '%s' "$valeur"
}

# Échappe un champ CSV selon RFC 4180 : guillemets doublés et champ encadré dès
# qu'il contient une virgule, un guillemet ou un saut de ligne.
echapper_csv() {
    local valeur="$1"
    if [[ "$valeur" == *'"'* || "$valeur" == *','* || "$valeur" == *$'\n'* ]]; then
        valeur="${valeur//\"/\"\"}"
        printf '"%s"' "$valeur"
    else
        printf '%s' "$valeur"
    fi
}

sortie_json() {
    local entree section cle valeur section_courante="" premiere_cle=1 incomplet="false"
    if (( NB_INDISPONIBLES > 0 )); then
        incomplet="true"
    fi
    printf '{\n'
    printf '  "script": "inventory.sh",\n'
    printf '  "version": "%s",\n' "$VERSION_SCRIPT"
    printf '  "date": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "hote": "%s",\n' "$(echapper_json "$HOTE_FQDN")"
    printf '  "incomplet": %s,\n' "$incomplet"
    printf '  "sections": {\n'
    for entree in "${RESULTATS[@]}"; do
        IFS=$'\t' read -r section cle valeur <<< "$entree"
        if [[ "$section" != "$section_courante" ]]; then
            if [[ -n "$section_courante" ]]; then
                printf '\n    },\n'
            fi
            printf '    "%s": {\n' "$(echapper_json "$section")"
            section_courante="$section"
            premiere_cle=1
        fi
        if (( premiere_cle )); then
            premiere_cle=0
        else
            printf ',\n'
        fi
        printf '      "%s": "%s"' "$(echapper_json "$cle")" "$(echapper_json "$valeur")"
    done
    if [[ -n "$section_courante" ]]; then
        printf '\n    }\n'
    fi
    printf '  }\n}\n'
}

sortie_csv() {
    local entree section cle valeur
    printf 'section,cle,valeur\n'
    for entree in "${RESULTATS[@]}"; do
        IFS=$'\t' read -r section cle valeur <<< "$entree"
        printf '%s,%s,%s\n' \
            "$(echapper_csv "$section")" "$(echapper_csv "$cle")" "$(echapper_csv "$valeur")"
    done
}

sortie_texte() {
    local entree section cle valeur section_courante=""
    for entree in "${RESULTATS[@]}"; do
        IFS=$'\t' read -r section cle valeur <<< "$entree"
        if [[ "$section" != "$section_courante" ]]; then
            section_courante="$section"
            printf '\n%s%s%s\n' "$C_INFO" "${section^^}" "$C_RESET"
        fi
        printf '  %-26s %s\n' "$cle" "$valeur"
    done
    printf '\n'
}

case "$FORMAT" in
    json) sortie_json ;;
    csv)  sortie_csv ;;
    *)    sortie_texte ;;
esac

if [[ -n "$CSV_FICHIER" ]]; then
    if ! sortie_csv > "$CSV_FICHIER"; then
        die "Impossible d'écrire le CSV dans ${CSV_FICHIER}"
    fi
    log_ok "CSV écrit dans ${CSV_FICHIER}"
fi

log_info "Inventaire de ${HOTE_FQDN} : ${#RESULTATS[@]} entrées, ${NB_AVERTISSEMENTS} donnée(s) secondaire(s) indisponible(s)"

if (( NB_INDISPONIBLES > 0 )); then
    log_warn "Inventaire partiel : ${NB_INDISPONIBLES} donnée(s) essentielle(s) manquante(s)"
    fin_script "Inventaire terminé (incomplet)"
    exit 1
fi

fin_script "Inventaire terminé"
exit 0
