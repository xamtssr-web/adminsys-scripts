#!/usr/bin/env bash
# =============================================================================
# lint.sh — Contrôle qualité de tout le dépôt
# -----------------------------------------------------------------------------
# Vérifie que chaque script est propre avant publication :
#   - Bash      : shellcheck en niveau « style » (le plus strict)
#   - PowerShell: analyse syntaxique par le parseur AST de PowerShell
#
# Pourquoi : un dépôt de scripts qui ne passe pas son propre linter perd toute
# crédibilité. Ce script est le même que celui exécuté par l'intégration
# continue (.github/workflows/lint.yml) : ce qui passe ici passe là-bas.
#
# Usage :
#   ./tests/lint.sh              # tout vérifier
#   ./tests/lint.sh --bash       # Bash uniquement
#   ./tests/lint.sh --powershell # PowerShell uniquement
#
# Codes retour : 0 = tout est propre, 1 = au moins un problème
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER_BASH=0
VERIFIER_PS=0
NB_PROBLEMES=0
NB_FICHIERS=0

if (( $# == 0 )); then
    VERIFIER_BASH=1
    VERIFIER_PS=1
else
    for option in "$@"; do
        case "$option" in
            --bash)       VERIFIER_BASH=1 ;;
            --powershell) VERIFIER_PS=1 ;;
            -h|--help)
                echo "Usage : $0 [--bash] [--powershell]"
                exit 0
                ;;
            *) echo "Option inconnue : $option" >&2; exit 2 ;;
        esac
    done
fi

# --- Bash --------------------------------------------------------------------
if (( VERIFIER_BASH )); then
    echo "=== Vérification des scripts Bash (shellcheck) ==="

    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "  ATTENTION : shellcheck n'est pas installé — vérification ignorée"
        echo "              installation : apt install shellcheck | brew install shellcheck"
        NB_PROBLEMES=$(( NB_PROBLEMES + 1 ))
    else
        while IFS= read -r fichier; do
            NB_FICHIERS=$(( NB_FICHIERS + 1 ))
            # Note : le fichier sourcé (lib/common.sh) est résolu relativement au
            # répertoire courant — on se place donc dans le dossier du script.
            dossier="$(dirname "$fichier")"
            nom="$(basename "$fichier")"
            # -x : suivre les fichiers sourcés pour éviter les faux positifs
            if resultat="$(cd "$dossier" && shellcheck -x -S style -f gcc "./$nom" 2>&1)"; then
                echo "  OK     ${fichier#"$RACINE"/}"
            else
                echo "  ECHEC  ${fichier#"$RACINE"/}"
                printf '%s\n' "$resultat" | sed 's/^/         /'
                NB_PROBLEMES=$(( NB_PROBLEMES + 1 ))
            fi
        done < <(find "$RACINE/bash" -name '*.sh' -type f | sort)
    fi
fi

# --- PowerShell --------------------------------------------------------------
if (( VERIFIER_PS )); then
    echo ""
    echo "=== Vérification des scripts PowerShell (parseur AST) ==="

    PWSH=""
    for candidat in pwsh powershell; do
        if command -v "$candidat" >/dev/null 2>&1; then
            PWSH="$candidat"
            break
        fi
    done

    if [[ -z "$PWSH" ]]; then
        echo "  ATTENTION : PowerShell n'est pas installé — vérification ignorée"
        echo "              installation : https://github.com/PowerShell/PowerShell/releases"
        NB_PROBLEMES=$(( NB_PROBLEMES + 1 ))
    else
        while IFS= read -r fichier; do
            NB_FICHIERS=$(( NB_FICHIERS + 1 ))
            sortie="$("$PWSH" -NoProfile -Command "
                \$erreurs = \$null; \$jetons = \$null
                [System.Management.Automation.Language.Parser]::ParseFile('$fichier', [ref]\$jetons, [ref]\$erreurs) | Out-Null
                if (\$erreurs -and \$erreurs.Count -gt 0) {
                    \$erreurs | ForEach-Object { 'ligne ' + \$_.Extent.StartLineNumber + ' : ' + \$_.Message }
                    exit 1
                }
                exit 0
            " 2>&1)" && statut=0 || statut=$?

            if (( statut == 0 )); then
                echo "  OK     ${fichier#"$RACINE"/}"
            else
                echo "  ECHEC  ${fichier#"$RACINE"/}"
                printf '%s\n' "$sortie" | sed 's/^/         /'
                NB_PROBLEMES=$(( NB_PROBLEMES + 1 ))
            fi
        done < <(find "$RACINE/powershell" -name '*.ps1' -type f | sort)
    fi
fi

# --- Bilan -------------------------------------------------------------------
echo ""
echo "-----------------------------------------------"
if (( NB_PROBLEMES == 0 )); then
    echo "Résultat : $NB_FICHIERS fichier(s) vérifié(s), aucun problème."
    exit 0
fi
echo "Résultat : $NB_PROBLEMES problème(s) détecté(s) sur $NB_FICHIERS fichier(s)."
exit 1
