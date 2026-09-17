#!/usr/bin/env bash
# =============================================================================
# linux-user-provisioning.sh — Création et mise à jour idempotentes de comptes
# -----------------------------------------------------------------------------
# Crée un compte Linux s'il n'existe pas, aligne ses attributs s'il existe
# déjà (commentaire, coquille, groupes secondaires, clés SSH autorisées,
# expiration, entrée sudoers dédiée), et propose une purge explicite des
# éléments obsolètes.
#
# Pourquoi : un « useradd » lancé à la main n'est pas rejouable. Le relancer
# casse le compte (ou échoue), et rien ne garantit que l'état final correspond
# à celui décrit dans la documentation d'exploitation. Un provisionnement
# idempotent, c'est la même commande pour créer et pour corriger — donc un
# état d'arrivée reproductible, versionnable dans un dépôt.
#
# Sécurité : toute suppression (purge des groupes, des clés ou de l'entrée
# sudoers obsolètes) exige --force. Le fichier sudoers écrit est toujours
# validé par « visudo -cf » avant installation, puis par un « visudo -c »
# global ; en cas de rejet, l'entrée est retirée et le système reste intact.
#
# Sémantique de --supprimer-obsolescence : l'existant est aligné sur la cible.
# La purge ne s'applique qu'aux familles explicitement décrites :
#   - groupes : seulement si --groupes est fourni (les autres sont retirés) ;
#   - clés SSH : seulement si au moins un --cle-ssh est fourni ;
#   - sudoers : toujours (l'entrée est retirée si --sudo est absent).
#
# Codes retour :
#   0 = compte conforme à l'état demandé
#   1 = échec d'exécution (droits, commande système, validation)
#   2 = paramètres invalides
#
# Exemples :
#   ./linux-user-provisioning.sh --utilisateur jdupont --commentaire "Jean Dupont"
#   ./linux-user-provisioning.sh -u deploy --groupes docker,sudo --sudo
#   ./linux-user-provisioning.sh -u ops --cle-ssh /root/cles/ops.pub --coquille /bin/bash
#   ./linux-user-provisioning.sh -u stagiaire --expiration 2026-12-31
#   ./linux-user-provisioning.sh -u ops --groupes ops --supprimer-obsolescence --force
# =============================================================================

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# --- Valeurs par défaut ------------------------------------------------------
readonly MOTIF_UTILISATEUR='^[a-z_][a-z0-9_-]{0,31}$'
readonly MOTIF_CLE='^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[a-z0-9-]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+'

UTILISATEUR=""
COMMENTAIRE=""
SPEC_GROUPES=""
SUDO=0
COQUILLE=""
EXPIRATION=""
PURGE=0
FORCE=0
SOURCES_CLES=()

GROUPES_DEMANDES=()
CLES_DEMANDEES=()
TEMPORAIRES=()
EXISTE=0
MAISON=""
GROUPE_PRIMAIRE=""
UID_COMPTE=""
MUTATIONS=0
ACTION="inchange"

usage() {
    entete_script "Crée ou met à jour un compte Linux de façon idempotente."
    cat >&2 <<'EOF'

Usage :
  linux-user-provisioning.sh --utilisateur <nom> [options]

Obligatoire :
  -u, --utilisateur <nom>        Nom du compte à provisionner

Options :
      --commentaire <texte>      Champ descriptif du compte (GECOS)
      --groupes <liste>          Groupes secondaires, séparés par des virgules
                                 ou des espaces (doivent exister sur l'hôte)
      --sudo                     Active une entrée sudoers dédiée :
                                 /etc/sudoers.d/<utilisateur> (ALL=(ALL:ALL) ALL)
      --cle-ssh <source>         Clé publique autorisée : chemin de fichier ou
                                 clé en clair (répétable)
      --coquille <chemin>        Interpréteur de connexion (doit figurer dans
                                 /etc/shells)
      --expiration <AAAA-MM-JJ>  Date d'expiration du compte
      --supprimer-obsolescence   Aligne l'existant sur la cible : retire les
                                 groupes, clés SSH et entrée sudoers non demandés
                                 (en exige --force)
      --force                    Confirme une action destructive
  -n, --dry-run                  Simulation : affiche sans rien modifier
  -q, --quiet                    N'affiche que les avertissements et erreurs
  -v, --verbose                  Affiche le détail des opérations
  -h, --help                     Affiche cette aide

Codes retour :
  0  compte conforme à l'état demandé
  1  échec d'exécution (privilèges, commande système, validation visudo)
  2  mauvaise utilisation (paramètres manquants ou invalides)

Exemples :
  linux-user-provisioning.sh --utilisateur jdupont --commentaire "Jean Dupont"
  linux-user-provisioning.sh -u deploy --groupes docker,sudo --sudo
  linux-user-provisioning.sh -u ops --cle-ssh /root/cles/ops.pub --dry-run
  linux-user-provisioning.sh -u stagiaire --expiration 2026-12-31
EOF
}

# --- Arguments ---------------------------------------------------------------
while (( $# > 0 )); do
    case "$1" in
        -u|--utilisateur)         [[ -n "${2:-}" ]] || die_usage "-u exige un nom de compte"; UTILISATEUR="$2"; shift 2 ;;
        --commentaire)            [[ -n "${2:-}" ]] || die_usage "--commentaire exige un texte"; COMMENTAIRE="$2"; shift 2 ;;
        --groupes)                [[ -n "${2:-}" ]] || die_usage "--groupes exige une liste"; SPEC_GROUPES="$2"; shift 2 ;;
        --sudo)                   SUDO=1; shift ;;
        --cle-ssh)                [[ -n "${2:-}" ]] || die_usage "--cle-ssh exige un fichier ou une clé"; SOURCES_CLES+=("$2"); shift 2 ;;
        --coquille)               [[ -n "${2:-}" ]] || die_usage "--coquille exige un chemin"; COQUILLE="$2"; shift 2 ;;
        --expiration)             [[ -n "${2:-}" ]] || die_usage "--expiration exige une date AAAA-MM-JJ"; EXPIRATION="$2"; shift 2 ;;
        --supprimer-obsolescence) PURGE=1; shift ;;
        --force)                  FORCE=1; shift ;;
        -n|--dry-run)             DRY_RUN=1; shift ;;
        -q|--quiet)               QUIET=1; shift ;;
        -v|--verbose)             VERBOSE=1; shift ;;
        -h|--help)                usage; exit 0 ;;
        *) usage; die_usage "Option inconnue : $1" ;;
    esac
done

# --- Validation des paramètres ----------------------------------------------
if [[ -z "$UTILISATEUR" ]]; then
    usage
    die_usage "Le nom du compte (--utilisateur) est requis."
fi
if [[ ! "$UTILISATEUR" =~ $MOTIF_UTILISATEUR ]]; then
    die_usage "Nom de compte invalide : ${UTILISATEUR} (minuscules, chiffres, « - » et « _ », 32 caractères au plus)"
fi

if (( PURGE )) && (( ! FORCE )); then
    die_usage "--supprimer-obsolescence retire des groupes, des clés et/ou une entrée sudoers : confirmez avec --force"
fi

if [[ -n "$COQUILLE" ]]; then
    if [[ ! -x "$COQUILLE" ]]; then
        die_usage "Coquille inexécutable : ${COQUILLE}"
    fi
    if ! grep -qxF -- "$COQUILLE" /etc/shells 2>/dev/null; then
        die_usage "Coquille absente de /etc/shells : ${COQUILLE} (ajoutez-la d'abord, ou choisissez un interpréteur déclaré)"
    fi
fi

if [[ -n "$EXPIRATION" ]]; then
    if [[ ! "$EXPIRATION" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        die_usage "--expiration attend le format AAAA-MM-JJ (reçu : ${EXPIRATION})"
    fi
    if [[ "$(date -d "$EXPIRATION" '+%Y-%m-%d' 2>/dev/null || true)" != "$EXPIRATION" ]]; then
        die_usage "Date inexistante : ${EXPIRATION}"
    fi
fi

if [[ -n "$SPEC_GROUPES" ]]; then
    IFS=' ' read -r -a GROUPES_DEMANDES <<< "${SPEC_GROUPES//,/ }"
fi

# --- Résolution des clés SSH -------------------------------------------------
# Chaque --cle-ssh est soit un fichier (toutes ses lignes utiles sont prises),
# soit une clé fournie en clair sur la ligne de commande.
resoudre_cles() {
    local source ligne
    for source in "${SOURCES_CLES[@]}"; do
        if [[ -f "$source" ]]; then
            while IFS= read -r ligne; do
                ligne="${ligne%$'\r'}"
                if [[ -z "$ligne" ]] || [[ "$ligne" == \#* ]]; then
                    continue
                fi
                if [[ ! "$ligne" =~ $MOTIF_CLE ]]; then
                    die_usage "Clé publique non reconnue dans ${source} : ${ligne}"
                fi
                CLES_DEMANDEES+=("$ligne")
            done < "$source"
        else
            if [[ "$source" != *" "* ]]; then
                die_usage "--cle-ssh : fichier introuvable et chaîne non assimilable à une clé : ${source}"
            fi
            if [[ ! "$source" =~ $MOTIF_CLE ]]; then
                die_usage "--cle-ssh : clé publique non reconnue (type attendu : ssh-ed25519, ssh-rsa, ecdsa-sha2-…)"
            fi
            CLES_DEMANDEES+=("$source")
        fi
    done
    if (( ${#CLES_DEMANDEES[@]} > 0 )); then
        log_info "clés publiques retenues : ${#CLES_DEMANDEES[@]}"
    fi
}

# --- Dépendances -------------------------------------------------------------
require_root
require_cmd useradd
require_cmd usermod
require_cmd getent
require_cmd awk
require_cmd install
if (( SUDO )) || (( PURGE )); then
    require_cmd visudo
fi
if (( PURGE )) && (( ${#GROUPES_DEMANDES[@]} > 0 )); then
    require_cmd gpasswd
fi

resoudre_cles

init_script "/var/log/linux-user-provisioning.log" "/var/run/linux-user-provisioning.lock"

# --- Utilitaires -------------------------------------------------------------
# Lance une commande via « run » (le mode simulation reste donc respecté) en
# forçant un IFS d'espace le temps de l'appel : l'IFS global du dépôt
# (« saut de ligne, tabulation ») ferait afficher la commande sur plusieurs
# lignes dans le journal et dans la sortie du mode simulation.
lancer() {
    IFS=' ' run "$@"
    MUTATIONS=$(( MUTATIONS + 1 ))
}

joindre_virgule() {
    local IFS=','
    printf '%s' "$*"
}

# Faux positif de shellcheck : il évalue le corps de la fonction avec l'état du
# tableau à l'endroit de la définition (vide ici, rempli plus bas dans le script).
# shellcheck disable=SC2317
nettoyer_temporaires() {
    local fichier
    (( ${#TEMPORAIRES[@]} > 0 )) || return 0
    for fichier in "${TEMPORAIRES[@]}"; do
        [[ -e "$fichier" ]] || continue
        rm -f "$fichier"
    done
}
trap nettoyer_temporaires EXIT

existe_utilisateur() {
    getent passwd "$1" >/dev/null 2>&1
}

# --- 1. État actuel ----------------------------------------------------------
log_step "1/7 État actuel du compte"
if existe_utilisateur "$UTILISATEUR"; then
    EXISTE=1
    IFS=':' read -r _ _ UID_COMPTE _ _ MAISON _ <<< "$(getent passwd "$UTILISATEUR")"
    GROUPE_PRIMAIRE="$(id -gn "$UTILISATEUR" 2>/dev/null || printf '%s' "$UTILISATEUR")"
    log_info "le compte ${UTILISATEUR} existe déjà (uid ${UID_COMPTE}, groupe ${GROUPE_PRIMAIRE}, maison ${MAISON})"
else
    MAISON="/home/${UTILISATEUR}"
    GROUPE_PRIMAIRE="$UTILISATEUR"
    log_info "le compte ${UTILISATEUR} n'existe pas encore (création prévue, maison ${MAISON})"
fi

# --- 2. Création ou mise à jour du compte ------------------------------------
log_step "2/7 Compte"
if (( EXISTE )); then
    GECOS_ACTUEL="$(getent passwd "$UTILISATEUR" | awk -F: '{print $5}')"
    COQUILLE_ACTUELLE="$(getent passwd "$UTILISATEUR" | awk -F: '{print $7}')"

    if [[ -n "$COMMENTAIRE" ]] && [[ "$GECOS_ACTUEL" != "$COMMENTAIRE" ]]; then
        log_info "commentaire : « ${GECOS_ACTUEL} » -> « ${COMMENTAIRE} »"
        if ! lancer usermod --comment "$COMMENTAIRE" "$UTILISATEUR"; then
            die "Échec de la mise à jour du commentaire de ${UTILISATEUR}."
        fi
    fi
    if [[ -n "$COQUILLE" ]] && [[ "$COQUILLE_ACTUELLE" != "$COQUILLE" ]]; then
        log_info "coquille : ${COQUILLE_ACTUELLE} -> ${COQUILLE}"
        if ! lancer usermod --shell "$COQUILLE" "$UTILISATEUR"; then
            die "Échec de la mise à jour de la coquille de ${UTILISATEUR}."
        fi
    fi
    if (( MUTATIONS == 0 )); then
        log_info "aucun attribut de compte à corriger"
    fi
else
    ARGS_USERADD=(--create-home)
    if [[ -n "$COMMENTAIRE" ]]; then
        ARGS_USERADD+=(--comment "$COMMENTAIRE")
    fi
    if [[ -n "$COQUILLE" ]]; then
        ARGS_USERADD+=(--shell "$COQUILLE")
    fi
    if [[ -n "$EXPIRATION" ]]; then
        ARGS_USERADD+=(--expiredate "$EXPIRATION")
    fi
    if ! lancer useradd "${ARGS_USERADD[@]}" "$UTILISATEUR"; then
        die "Échec de la création du compte ${UTILISATEUR}."
    fi
    ACTION="cree"
    log_info "compte ${UTILISATEUR} créé"
fi

# --- 3. Groupes secondaires --------------------------------------------------
log_step "3/7 Groupes secondaires"
groupes_actuels=()
if (( EXISTE )); then
    IFS=' ' read -r -a groupes_actuels <<< "$(id -nG "$UTILISATEUR" 2>/dev/null || true)"
fi

if (( ${#GROUPES_DEMANDES[@]} == 0 )); then
    log_info "aucun groupe demandé (--groupes absent)"
else
    for groupe in "${GROUPES_DEMANDES[@]}"; do
        if [[ -z "$groupe" ]]; then
            continue
        fi
        if ! getent group "$groupe" >/dev/null 2>&1; then
            die_usage "Groupe inexistant sur cet hôte : ${groupe} (créez-le au préalable)"
        fi
        if contient "$groupe" "${groupes_actuels[@]:-}"; then
            log_debug "groupe ${groupe} : déjà membre"
        else
            log_info "ajout au groupe ${groupe}"
            if ! lancer usermod -aG "$groupe" "$UTILISATEUR"; then
                die "Échec de l'ajout de ${UTILISATEUR} au groupe ${groupe}."
            fi
        fi
    done
fi

if (( PURGE )); then
    if (( ${#GROUPES_DEMANDES[@]} == 0 )); then
        log_info "purge des groupes ignorée : --groupes n'a pas été fourni"
    else
        for groupe in "${groupes_actuels[@]:-}"; do
            if [[ -z "$groupe" ]] || [[ "$groupe" == "$GROUPE_PRIMAIRE" ]]; then
                continue
            fi
            if ! contient "$groupe" "${GROUPES_DEMANDES[@]:-}"; then
                log_warn "retrait du groupe obsolète ${groupe}"
                if ! lancer gpasswd --delete "$UTILISATEUR" "$groupe"; then
                    die "Échec du retrait de ${UTILISATEUR} du groupe ${groupe}."
                fi
            fi
        done
    fi
fi

# --- 4. Clés SSH autorisées --------------------------------------------------
log_step "4/7 Clés SSH autorisées"
if (( ${#CLES_DEMANDEES[@]} == 0 )); then
    log_info "aucune clé fournie : authorized_keys inchangé"
else
    DOSSIER_SSH="${MAISON}/.ssh"
    FICHIER_AUTORISE="${DOSSIER_SSH}/authorized_keys"
    cles_conservees=()

    if (( PURGE )); then
        cles_conservees=("${CLES_DEMANDEES[@]}")
        log_warn "purge demandée : authorized_keys sera réécrit avec ${#CLES_DEMANDEES[@]} clé(s)"
    else
        if [[ -r "$FICHIER_AUTORISE" ]]; then
            while IFS= read -r ligne_cle; do
                if [[ -n "$ligne_cle" ]]; then
                    cles_conservees+=("$ligne_cle")
                fi
            done < "$FICHIER_AUTORISE"
        fi
        for cle in "${CLES_DEMANDEES[@]}"; do
            if contient "$cle" "${cles_conservees[@]:-}"; then
                log_debug "clé déjà présente : ${cle:0:40}…"
            else
                log_info "ajout d'une clé : ${cle:0:40}…"
                cles_conservees+=("$cle")
            fi
        done
    fi

    FICHIER_TMP="$(mktemp "${TMPDIR:-/tmp}/cles-autorisees.XXXXXX")"
    TEMPORAIRES+=("$FICHIER_TMP")
    printf '%s\n' "${cles_conservees[@]}" > "$FICHIER_TMP"

    if [[ -r "$FICHIER_AUTORISE" ]] && cmp -s "$FICHIER_TMP" "$FICHIER_AUTORISE"; then
        log_info "authorized_keys déjà conforme (${#cles_conservees[@]} clé(s))"
    else
        log_info "${#cles_conservees[@]} clé(s) dans ${FICHIER_AUTORISE}"
        if ! lancer install -d -m 0700 -o "$UTILISATEUR" -g "$GROUPE_PRIMAIRE" "$DOSSIER_SSH"; then
            die "Échec de la préparation de ${DOSSIER_SSH}."
        fi
        if ! lancer install -m 0600 -o "$UTILISATEUR" -g "$GROUPE_PRIMAIRE" "$FICHIER_TMP" "$FICHIER_AUTORISE"; then
            die "Échec de l'écriture de ${FICHIER_AUTORISE}."
        fi
    fi
fi

# --- 5. Entrée sudoers dédiée ------------------------------------------------
log_step "5/7 Entrée sudoers"
FICHIER_SUDOERS="/etc/sudoers.d/${UTILISATEUR}"
SUDOERS_ATTENDU="$(printf '# Géré par %s — ne pas modifier à la main\n%s ALL=(ALL:ALL) ALL\n' \
    "$SCRIPT_NAME" "$UTILISATEUR")"

if (( SUDO )); then
    ACTUEL_SUDOERS=""
    if [[ -r "$FICHIER_SUDOERS" ]]; then
        ACTUEL_SUDOERS="$(< "$FICHIER_SUDOERS")"
    fi

    if [[ "$ACTUEL_SUDOERS" == "$SUDOERS_ATTENDU" ]]; then
        log_info "entrée sudoers déjà conforme : ${FICHIER_SUDOERS}"
    elif (( DRY_RUN )); then
        log_info "[simulation] écriture de ${FICHIER_SUDOERS} : « ${UTILISATEUR} ALL=(ALL:ALL) ALL » validée par visudo"
    else
        FICHIER_SUDOERS_TMP="$(mktemp /etc/sudoers.d/.tmp-provisionnement.XXXXXX)"
        TEMPORAIRES+=("$FICHIER_SUDOERS_TMP")
        printf '%s\n' "$SUDOERS_ATTENDU" > "$FICHIER_SUDOERS_TMP"
        chmod 0440 "$FICHIER_SUDOERS_TMP"

        if ! visudo -cf "$FICHIER_SUDOERS_TMP" >/dev/null 2>&1; then
            log_error "visudo refuse le contenu généré pour ${FICHIER_SUDOERS} :"
            visudo -cf "$FICHIER_SUDOERS_TMP" >&2 || true
            die "Écriture sudoers abandonnée : le contenu n'est pas un sudoers valide."
        fi
        if ! install -m 0440 -o root -g root "$FICHIER_SUDOERS_TMP" "$FICHIER_SUDOERS"; then
            die "Échec de l'installation de ${FICHIER_SUDOERS}."
        fi
        MUTATIONS=$(( MUTATIONS + 1 ))
        log_info "entrée sudoers installée : ${FICHIER_SUDOERS}"

        if ! visudo -c >/dev/null 2>&1; then
            log_error "« visudo -c » signale une configuration sudoers invalide après l'ajout :"
            visudo -c >&2 || true
            rm -f "$FICHIER_SUDOERS"
            log_warn "L'entrée ${FICHIER_SUDOERS} a été retirée : la configuration sudoers est laissée intacte."
            die "Provisionnement sudoers annulé (reprise manuelle nécessaire)."
        fi
        log_ok "configuration sudoers validée par « visudo -c »"
    fi
else
    if (( PURGE )); then
        if [[ -e "$FICHIER_SUDOERS" ]]; then
            log_warn "retrait de l'entrée sudoers non demandée : ${FICHIER_SUDOERS}"
            if ! lancer rm -f "$FICHIER_SUDOERS"; then
                die "Échec du retrait de ${FICHIER_SUDOERS}."
            fi
            if (( ! DRY_RUN )) && ! visudo -c >/dev/null 2>&1; then
                log_error "« visudo -c » refuse la configuration après le retrait de ${FICHIER_SUDOERS} :"
                visudo -c >&2 || true
                die "Corrigez /etc/sudoers manuellement : la configuration globale est invalide."
            fi
        else
            log_debug "aucune entrée sudoers à retirer"
        fi
    else
        log_info "entrée sudoers non demandée (--sudo absent)"
    fi
fi

# --- 6. Expiration du compte -------------------------------------------------
log_step "6/7 Expiration du compte"
if [[ -z "$EXPIRATION" ]]; then
    log_info "aucune date d'expiration demandée : valeur inchangée"
else
    JOUR_CIBLE=$(( $(date -d "$EXPIRATION" '+%s') / 86400 ))
    JOUR_ACTUEL="$(getent shadow "$UTILISATEUR" 2>/dev/null | awk -F: '{print $8}' || true)"

    if [[ "$JOUR_ACTUEL" == "$JOUR_CIBLE" ]]; then
        log_info "expiration déjà positionnée au ${EXPIRATION}"
    else
        log_info "expiration : ${JOUR_ACTUEL:-jamais} -> ${EXPIRATION}"
        if ! lancer usermod --expiredate "$EXPIRATION" "$UTILISATEUR"; then
            die "Échec de la mise à jour de l'expiration de ${UTILISATEUR}."
        fi
    fi
fi

# --- 7. Bilan ----------------------------------------------------------------
log_step "7/7 Bilan"
if [[ "$ACTION" != "cree" ]] && (( MUTATIONS > 0 )); then
    ACTION="mis-a-jour"
fi

if (( DRY_RUN )); then
    log_warn "mode simulation : aucune modification n'a été appliquée"
fi

if (( ${#GROUPES_DEMANDES[@]} == 0 )); then
    LISTE_GROUPES="-"
else
    LISTE_GROUPES="$(joindre_virgule "${GROUPES_DEMANDES[@]}")"
fi
if (( SUDO )); then
    SUDO_AFFICHE="oui"
else
    SUDO_AFFICHE="non"
fi
if (( EXISTE )); then
    UID_AFFICHE="$UID_COMPTE"
else
    UID_AFFICHE="$(getent passwd "$UTILISATEUR" 2>/dev/null | awk -F: '{print $3}' || true)"
    UID_AFFICHE="${UID_AFFICHE:--}"
fi

printf 'utilisateur=%s action=%s uid=%s maison=%s groupes=%s sudo=%s expiration=%s\n' \
    "$UTILISATEUR" "$ACTION" "$UID_AFFICHE" "$MAISON" "$LISTE_GROUPES" "$SUDO_AFFICHE" \
    "${EXPIRATION:-jamais}"

fin_script "Compte ${UTILISATEUR} : ${ACTION}"
exit 0
