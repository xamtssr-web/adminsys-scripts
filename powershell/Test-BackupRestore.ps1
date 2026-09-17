<#
.SYNOPSIS
    Teste réellement une sauvegarde en la restaurant, et mesure le temps de reprise (RTO).

.DESCRIPTION
    Une sauvegarde jamais restaurée n'est pas une sauvegarde : c'est une
    hypothèse. Ce script restaure l'archive dans un dossier temporaire isolé,
    vérifie que le contenu attendu est bien là, compare les empreintes
    SHA-256 si un manifeste est fourni, chronomètre l'opération et conclut.

    Le script n'écrit jamais ailleurs que dans son dossier temporaire, et il
    le supprime systématiquement à la fin (sauf -GarderRestauration).

    Le temps mesuré est un RTO de restauration : c'est la donnée qu'on demande
    en entretien et en audit, et personne ne l'a parce que personne ne teste.

.PARAMETER Archive
    Sauvegarde à tester : .zip, .tar, .tar.gz ou .tgz.

.PARAMETER Destination
    Dossier de restauration. Par défaut un répertoire temporaire créé par le
    script et supprimé à la fin.

.PARAMETER ManifesteCsv
    Manifeste CSV (colonnes Chemin, Empreinte) décrivant les fichiers attendus
    et leur empreinte SHA-256. Active la comparaison d'empreintes après
    restauration — c'est le niveau de vérification le plus élevé.

.PARAMETER FichierAttendu
    Chemin relatif qui doit se trouver dans la sauvegarde (répétable).
    Exemple : 'base/ntds.dit', 'SYSVOL/Policies'.

.PARAMETER RtoMaxSecondes
    Seuil d'alerte : si la restauration dépasse cette durée, le test échoue.
    Défaut : 1800 (30 minutes).

.PARAMETER GarderRestauration
    Conserve le dossier restauré pour inspection manuelle. Le script indique
    alors où il se trouve et ne le supprime pas.

.PARAMETER RapportCsv
    Exporte le résultat du test au format CSV (une ligne par vérification).

.PARAMETER AnalyseSeulement
    N'extrait rien : décrit l'archive (nombre d'entrées, taille décompressée
    estimée, présence des fichiers attendus) en listant le contenu. Utile pour
    un premier contrôle rapide, beaucoup plus rapide qu'une restauration.

.EXAMPLE
    .\Test-BackupRestore.ps1 -Archive \\nas\sauvegardes\serveur-01_2026-09-17.tar.gz

    Test complet : restauration en temporaire, mesure du RTO, nettoyage.

.EXAMPLE
    .\Test-BackupRestore.ps1 -Archive .\sauvegarde.zip -ManifesteCsv .\manifeste.csv `
        -FichierAttendu 'base/ntds.dit' -FichierAttendu 'SYSVOL' `
        -RtoMaxSecondes 900 -RapportCsv .\test-restauration.csv

    Test avec vérification d'empreintes, deux fichiers obligatoires et seuil de
    15 minutes, résultat exporté pour l'audit.

.EXAMPLE
    .\Test-BackupRestore.ps1 -Archive .\sauvegarde.zip -AnalyseSeulement

    Contrôle rapide sans restauration.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : PowerShell 5.1+ ou 7+. Pour .tar/.tar.gz, utilise tar.exe
                  (fourni avec Windows 10 1803+ et Windows Server 2019+).
    Version     : 1.0
    Codes retour: 0 = sauvegarde restaurable et conforme
                  1 = restaurée mais avec des écarts (fichiers manquants, RTO dépassé)
                  2 = sauvegarde NON restaurable (échec du test)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Archive à tester (.zip, .tar, .tar.gz, .tgz)")]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$Archive,

    [Parameter(Mandatory = $false)]
    [string]$Destination,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$ManifesteCsv,

    [Parameter(Mandatory = $false)]
    [string[]]$FichierAttendu = @(),

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 86400)]
    [int]$RtoMaxSecondes = 1800,

    [Parameter(Mandatory = $false)]
    [switch]$GarderRestauration,

    [Parameter(Mandatory = $false)]
    [string]$RapportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$AnalyseSeulement
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Infrastructure du rapport ----------------------------------------------
$verifications = [System.Collections.Generic.List[object]]::new()
$nbEchecs = 0
$nbAvertissements = 0

function Add-Verification {
    param(
        [Parameter(Mandatory = $true)][string]$Controle,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'ATTENTION', 'ECHEC')][string]$Statut,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $couleur = switch ($Statut) {
        'OK'        { 'Green' }
        'ATTENTION' { 'Yellow' }
        'ECHEC'     { 'Red' }
    }
    Write-Host ("  [{0,-9}] {1,-34} {2}" -f $Statut, $Controle, $Detail) -ForegroundColor $couleur

    $script:verifications.Add([pscustomobject]@{
        Controle = $Controle
        Statut   = $Statut
        Detail   = $Detail
        Date     = (Get-Date)
    })

    if ($Statut -eq 'ECHEC') { $script:nbEchecs++ }
    if ($Statut -eq 'ATTENTION') { $script:nbAvertissements++ }
}

# Formate une durée en texte lisible
function Format-Duree {
    param([double]$Secondes)
    if ($Secondes -lt 60) { return ("{0:N1} s" -f $Secondes) }
    $minutes = [math]::Floor($Secondes / 60)
    $reste = $Secondes - ($minutes * 60)
    if ($minutes -lt 60) { return ("{0} min {1:N0} s" -f $minutes, $reste) }
    $heures = [math]::Floor($minutes / 60)
    return ("{0} h {1} min" -f $heures, ($minutes % 60))
}

# --- En-tête ----------------------------------------------------------------
$fichier = Get-Item -Path $Archive
$tailleArchive = $fichier.Length

Write-Host ""
Write-Host "=== Test de restauration de sauvegarde ===" -ForegroundColor White
Write-Host ("Archive   : {0}" -f $fichier.FullName)
Write-Host ("Taille    : {0:N1} Mio" -f ($tailleArchive / 1MB))
Write-Host ("Empreinte : {0}" -f (Get-FileHash -Path $fichier.FullName -Algorithm SHA256).Hash)
Write-Host ""

# --- Détermination du type d'archive ----------------------------------------
$extension = $fichier.Extension.ToLower()
$estZip = $extension -eq '.zip'
$estTar = $extension -in @('.tar', '.tgz') -or $fichier.Name -match '\.tar\.(gz|zst|bz2|xz)$'

if (-not $estZip -and -not $estTar) {
    Write-Error "Format d'archive non pris en charge : $($fichier.Name). Formats acceptés : .zip, .tar, .tar.gz, .tgz"
    exit 2
}

# tar.exe est fourni avec Windows 10 1803+ et Windows Server 2019+
if ($estTar) {
    $tarExe = Get-Command tar.exe -ErrorAction SilentlyContinue
    if (-not $tarExe) {
        Write-Error "tar.exe introuvable. Il est fourni avec Windows 10 1803+ / Windows Server 2019+. Pour les versions antérieures, utilisez une archive .zip."
        exit 2
    }
}

# --- Analyse du contenu -----------------------------------------------------
Write-Host "==> Analyse de l'archive" -ForegroundColor Cyan

$entrees = @()
$tailleDecompressee = 0

if ($AnalyseSeulement) {
    if ($estZip) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($fichier.FullName)
        try {
            $entrees = $zip.Entries | ForEach-Object { $_.FullName }
            $tailleDecompressee = ($zip.Entries | Measure-Object -Property Length -Sum).Sum
        }
        finally {
            $zip.Dispose()
        }
    }
    else {
        $entrees = & tar.exe -tf $fichier.FullName
    }

    Add-Verification -Controle 'Lecture de la table des matières' -Statut 'OK' `
        -Detail ("{0} entrée(s) listée(s)" -f $entrees.Count)

    if ($tailleDecompressee -gt 0) {
        Add-Verification -Controle 'Taille décompressée' -Statut 'OK' `
            -Detail ("{0:N1} Mio (ratio {1:N1}x)" -f ($tailleDecompressee / 1MB), ($tailleDecompressee / $tailleArchive))
    }

    foreach ($attendu in $FichierAttendu) {
        $normalise = $attendu -replace '\\', '/'
        $present = $entrees | Where-Object { ($_ -replace '\\', '/') -like "*$normalise*" }
        if ($present) {
            Add-Verification -Controle "Présence : $attendu" -Statut 'OK' `
                -Detail ("{0} entrée(s) correspondante(s)" -f @($present).Count)
        }
        else {
            Add-Verification -Controle "Présence : $attendu" -Statut 'ECHEC' `
                -Detail 'introuvable dans la table des matières'
        }
    }

    Write-Host ""
    Write-Host "Analyse terminée — aucune restauration effectuée." -ForegroundColor Cyan
    if ($RapportCsv) {
        $verifications | Export-Csv -Path $RapportCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
        Write-Host ("Rapport exporté : {0}" -f $RapportCsv)
    }
    if ($nbEchecs -gt 0) { exit 2 }
    if ($nbAvertissements -gt 0) { exit 1 }
    exit 0
}

# --- Restauration -----------------------------------------------------------
$temporaire = $false
if (-not $Destination) {
    $Destination = Join-Path ([System.IO.Path]::GetTempPath()) ("test-restauration-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $temporaire = $true
}

Write-Host ""
Write-Host "==> Restauration" -ForegroundColor Cyan
Write-Host ("Destination : {0}{1}" -f $Destination, $(if ($temporaire) { ' (temporaire)' } else { '' }))

if (Test-Path $Destination) {
    if ($temporaire) {
        Remove-Item -Path $Destination -Recurse -Force
    }
    else {
        Write-Warning "Le dossier de destination existe déjà : son contenu sera complété."
    }
}
New-Item -Path $Destination -ItemType Directory -Force | Out-Null

$chrono = [System.Diagnostics.Stopwatch]::StartNew()
$restaurationReussie = $true

try {
    if ($estZip) {
        Expand-Archive -Path $fichier.FullName -DestinationPath $Destination -Force
    }
    else {
        & tar.exe -xf $fichier.FullName -C $Destination
        if ($LASTEXITCODE -ne 0) {
            throw "tar.exe a retourné le code $LASTEXITCODE"
        }
    }
}
catch {
    $restaurationReussie = $false
    $chrono.Stop()
    Add-Verification -Controle 'Extraction de l archive' -Statut 'ECHEC' `
        -Detail $_.Exception.Message
}
finally {
    if ($chrono.IsRunning) { $chrono.Stop() }
}

if ($restaurationReussie) {
    Add-Verification -Controle 'Extraction de l''archive' -Statut 'OK' `
        -Detail ("terminée en {0}" -f (Format-Duree $chrono.Elapsed.TotalSeconds))
}

# --- Vérifications du contenu restauré --------------------------------------
$fichiersRestatures = @()
$tailleRestaturee = 0

if ($restaurationReussie) {
    Write-Host ""
    Write-Host "==> Vérifications du contenu restauré" -ForegroundColor Cyan

    $fichiersRestatures = @(Get-ChildItem -Path $Destination -Recurse -File -ErrorAction SilentlyContinue)
    $tailleRestaturee = ($fichiersRestatures | Measure-Object -Property Length -Sum).Sum
    if (-not $tailleRestaturee) { $tailleRestaturee = 0 }

    Add-Verification -Controle 'Contenu restauré' -Statut 'OK' `
        -Detail ("{0} fichier(s), {1:N1} Mio" -f $fichiersRestatures.Count, ($tailleRestaturee / 1MB))

    # 1. Fichiers explicitement attendus
    foreach ($attendu in $FichierAttendu) {
        $cheminComplet = Join-Path $Destination $attendu
        $correspondances = @($fichiersRestatures | Where-Object { $_.FullName -like "*$attendu*" })
        if ((Test-Path $cheminComplet) -or $correspondances.Count -gt 0) {
            Add-Verification -Controle "Présence : $attendu" -Statut 'OK' `
                -Detail $(if (Test-Path $cheminComplet) { 'présent' } else { "$($correspondances.Count) correspondance(s)" })
        }
        else {
            Add-Verification -Controle "Présence : $attendu" -Statut 'ECHEC' `
                -Detail 'absent après restauration — la sauvegarde est incomplète'
        }
    }

    # 2. Comparaison d'empreintes si un manifeste est fourni
    if ($ManifesteCsv) {
        $manifeste = Import-Csv -Path $ManifesteCsv -Delimiter ';' -Encoding UTF8
        if (-not $manifeste -or -not ($manifeste[0].PSObject.Properties.Name -contains 'Chemin')) {
            Add-Verification -Controle 'Manifeste' -Statut 'ATTENTION' `
                -Detail 'manifeste illisible ou colonne « Chemin » absente — comparaison ignorée'
        }
        else {
            $conformes = 0
            $divergents = 0
            $absents = 0

            foreach ($ligne in $manifeste) {
                $cible = Join-Path $Destination $ligne.Chemin
                if (-not (Test-Path $cible)) {
                    $absents++
                    continue
                }
                if (-not $ligne.Empreinte) {
                    $conformes++
                    continue
                }
                $empreinte = (Get-FileHash -Path $cible -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if ($empreinte -eq $ligne.Empreinte) { $conformes++ } else { $divergents++ }
            }

            if ($divergents -eq 0 -and $absents -eq 0) {
                Add-Verification -Controle 'Empreintes SHA-256' -Statut 'OK' `
                    -Detail "$conformes/$($manifeste.Count) fichier(s) identiques au manifeste"
            }
            else {
                Add-Verification -Controle 'Empreintes SHA-256' -Statut 'ECHEC' `
                    -Detail "$conformes conformes, $divergents divergents, $absents absent(s)"
            }
        }
    }
    else {
        Add-Verification -Controle 'Empreintes SHA-256' -Statut 'ATTENTION' `
            -Detail 'aucun manifeste fourni — intégrité du contenu non vérifiable'
    }
}

# --- RTO --------------------------------------------------------------------
$duree = $chrono.Elapsed.TotalSeconds
Write-Host ""
Write-Host "==> Temps de reprise" -ForegroundColor Cyan

if ($duree -le $RtoMaxSecondes) {
    Add-Verification -Controle 'RTO constaté' -Statut 'OK' `
        -Detail ("{0} (seuil {1})" -f (Format-Duree $duree), (Format-Duree $RtoMaxSecondes))
}
else {
    Add-Verification -Controle 'RTO constaté' -Statut 'ATTENTION' `
        -Detail ("{0} — dépasse le seuil de {1}" -f (Format-Duree $duree), (Format-Duree $RtoMaxSecondes))
}

# --- Nettoyage --------------------------------------------------------------
if ($temporaire -and -not $GarderRestauration) {
    Remove-Item -Path $Destination -Recurse -Force -ErrorAction SilentlyContinue
    Add-Verification -Controle 'Nettoyage' -Statut 'OK' -Detail 'dossier temporaire supprimé'
}
else {
    Add-Verification -Controle 'Nettoyage' -Statut 'OK' -Detail "conservé : $Destination"
}

# --- Bilan ------------------------------------------------------------------
Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White

if ($nbEchecs -gt 0) {
    Write-Host ("SAUVEGARDE NON EXPLOITABLE — {0} échec(s), {1} avertissement(s)" -f $nbEchecs, $nbAvertissements) -ForegroundColor Red
}
elseif ($nbAvertissements -gt 0) {
    Write-Host ("Sauvegarde restaurée avec réserves — {0} avertissement(s)" -f $nbAvertissements) -ForegroundColor Yellow
}
else {
    Write-Host "Sauvegarde restaurable et conforme." -ForegroundColor Green
}

Write-Host ("Fichiers restaurés : {0}" -f $fichiersRestatures.Count)
Write-Host ("Taille restaurée   : {0:N1} Mio" -f ($tailleRestaturee / 1MB))
Write-Host ("RTO mesuré         : {0}" -f (Format-Duree $duree))

if ($RapportCsv) {
    $verifications | Export-Csv -Path $RapportCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
    Write-Host ("`nRapport exporté : {0}" -f $RapportCsv)
}

$verifications | Where-Object { $_.Statut -ne 'OK' }

if ($nbEchecs -gt 0) { exit 2 }
if ($nbAvertissements -gt 0) { exit 1 }
exit 0
