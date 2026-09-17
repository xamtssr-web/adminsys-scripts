<#
.SYNOPSIS
    Sauvegarde toutes les stratégies de groupe du domaine avec vérification.

.DESCRIPTION
    Réalise une sauvegarde complète et horodatée de l'ensemble des objets de
    stratégie de groupe (GPO) du domaine via Backup-GPO, puis :

      - écrit un manifeste CSV (nom, identifiant, horodatage, chemin, statut) ;
      - VÉRIFIE que chaque GPO possède bien son dossier de sauvegarde et son
        fichier Backup.xml — une sauvegarde « réussie » mais illisible est pire
        qu'un échec, car elle donne une fausse sécurité ;
      - archive éventuellement le dossier complet en .zip daté (-Compresser) ;
      - supprime éventuellement les sauvegardes plus anciennes que N jours
        (-RetentionJours), en respectant -WhatIf / -Confirm.

    Le script est à planifier (tâche planifiée hebdomadaire) : une sauvegarde GPO
    qui n'est jamais testée ne vaut rien le jour où il faut restaurer une
    stratégie supprimée par erreur.

.PARAMETER CheminSauvegarde
    Dossier racine des sauvegardes. Un sous-dossier horodaté y est créé à chaque
    exécution : GPO_Backup_<domaine>_<année><mois><jour>-<heure><minute><seconde>.
    Défaut : .\Sauvegardes-GPO à côté du script.

.PARAMETER Commentaire
    Commentaire attaché à chaque sauvegarde, visible dans la console GPMC lors
    d'une restauration. Défaut : « Sauvegarde automatique des GPO ».

.PARAMETER Compresser
    Produit une archive zip datée à côté du dossier de sauvegarde. Utile pour
    déposer la sauvegarde sur un partage distant ou une bande.

.PARAMETER RetentionJours
    Supprime les sauvegardes (dossiers et archives) plus anciennes que ce nombre
    de jours. Par défaut, aucune suppression n'est effectuée.

.PARAMETER Serveur
    Contrôleur de domaine à interroger (défaut : le contrôleur en cours).

.EXAMPLE
    .\Export-GPOBackup.ps1

    Sauvegarde complète dans .\Sauvegardes-GPO, avec manifeste et vérification.

.EXAMPLE
    .\Export-GPOBackup.ps1 -CheminSauvegarde D:\Sauvegardes\GPO -Compresser `
        -RetentionJours 90 -Commentaire 'Sauvegarde hebdomadaire - serveur FICHIER01'

    Sauvegarde archivée, avec purge des sauvegardes de plus de 90 jours.

.EXAMPLE
    .\Export-GPOBackup.ps1 -RetentionJours 30 -WhatIf

    Montre les sauvegardes qui seraient purgées, sans rien supprimer.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : console GPMC / RSAT (module GroupPolicy), droits de sauvegarde
                  des GPO (groupe Domain Admins ou délégation « création,
                  suppression et gestion des GPO »)
    Version     : 1.0
    Codes retour: 0 = toutes les GPO sauvegardées et vérifiées,
                  1 = sauvegarde partielle (au moins un échec ou une vérification négative),
                  2 = échec global (aucune GPO sauvegardée)
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false)]
    [string]$CheminSauvegarde,

    [Parameter(Mandatory = $false)]
    [string]$Commentaire = 'Sauvegarde automatique des GPO',

    [Parameter(Mandatory = $false)]
    [switch]$Compresser,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$RetentionJours,

    [Parameter(Mandatory = $false)]
    [string]$Serveur
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Chargement des modules --------------------------------------------------
try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Host "[ERREUR] Le module GroupPolicy est introuvable." -ForegroundColor Red
    Write-Host "         Installez la console GPMC / RSAT :" -ForegroundColor Red
    Write-Host "         Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0" -ForegroundColor DarkGray
    Write-Host "         Détail : $($_.Exception.Message)" -ForegroundColor DarkGray
    exit 2
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "[ERREUR] Le module ActiveDirectory est introuvable : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

$parametresAD = @{}
if ($Serveur) { $parametresAD['Server'] = $Serveur }

# --- Préparation du dossier de destination -----------------------------------

if (-not $CheminSauvegarde) {
    $racine = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $CheminSauvegarde = Join-Path $racine 'Sauvegardes-GPO'
}

if (-not (Test-Path -Path $CheminSauvegarde)) {
    New-Item -Path $CheminSauvegarde -ItemType Directory -Force | Out-Null
    Write-Verbose "Dossier racine créé : $CheminSauvegarde"
}

try {
    $domaine = Get-ADDomain @parametresAD
}
catch {
    Write-Host "[ERREUR] Domaine injoignable : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

$horodatage = Get-Date -Format 'yyyyMMdd-HHmmss'
$nomDossier = "GPO_Backup_{0}_{1}" -f $domaine.Name, $horodatage
$dossier = Join-Path $CheminSauvegarde $nomDossier

if (-not $PSCmdlet.ShouldProcess($dossier, "Sauvegarde de toutes les GPO du domaine $($domaine.DNSRoot)")) {
    # Mode -WhatIf : aucune écriture, on s'arrête proprement après avoir annoncé la cible
    Write-Host ""
    Write-Host "Simulation terminée : aucune sauvegarde effectuée." -ForegroundColor Yellow
    exit 0
}

New-Item -Path $dossier -ItemType Directory -Force | Out-Null

Write-Host ""
Write-Host ("Sauvegarde des GPO — domaine {0}" -f $domaine.DNSRoot) -ForegroundColor White
Write-Host ("Destination : {0}" -f $dossier)

# --- Inventaire des GPO ------------------------------------------------------

try {
    $gpos = @(Get-GPO -All @parametresAD | Sort-Object DisplayName)
}
catch {
    Write-Host "[ERREUR] Lecture des GPO impossible : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

if ($gpos.Count -eq 0) {
    Write-Host "[ATTENTION] Aucune GPO retournée par l'annuaire." -ForegroundColor Yellow
    exit 2
}

Write-Host ("{0} stratégie(s) de groupe à sauvegarder" -f $gpos.Count)
Write-Host ""

# --- Sauvegarde GPO par GPO --------------------------------------------------

$manifeste = [System.Collections.Generic.List[object]]::new()
$nbOk = 0
$nbEchecs = 0
$nbNonVerifiees = 0

foreach ($gpo in $gpos) {

    $entree = [pscustomobject]@{
        Nom          = $gpo.DisplayName
        Identifiant  = $gpo.Id
        Horodatage   = $null
        Chemin       = $null
        Statut       = 'ECHEC'
        Verification = 'non effectuée'
        DetailErreur = $null
    }

    try {
        $sauvegarde = Backup-GPO -Guid $gpo.Id -Path $dossier -Comment $Commentaire @parametresAD

        $entree.Horodatage = $sauvegarde.Timestamp
        $entree.Chemin = $sauvegarde.BackupDirectory
        $entree.Statut = 'Sauvegardee'

        # Vérification : le dossier de sauvegarde doit contenir les fichiers
        # que GPMC utilisera lors d'une restauration.
        $cheminBackup = $sauvegarde.BackupDirectory
        if ($cheminBackup -and (Test-Path -Path (Join-Path $cheminBackup 'Backup.xml'))) {
            $entree.Verification = 'OK'
            $nbOk++
            Write-Host ("  [OK]    {0}" -f $gpo.DisplayName) -ForegroundColor Green
        }
        else {
            $entree.Verification = 'Backup.xml absent'
            $nbNonVerifiees++
            Write-Warning ("  [ATTENTION] {0} : sauvegarde annoncée mais Backup.xml introuvable" -f $gpo.DisplayName)
        }
    }
    catch {
        $nbEchecs++
        $entree.DetailErreur = $_.Exception.Message
        Write-Warning ("  [ECHEC] {0} : {1}" -f $gpo.DisplayName, $_.Exception.Message)
    }

    $manifeste.Add($entree)
}

# --- Manifeste ---------------------------------------------------------------

$cheminManifeste = Join-Path $dossier 'manifeste-gpo.csv'
$manifeste | Export-Csv -Path $cheminManifeste -NoTypeInformation -Delimiter ';' -Encoding UTF8

# Contrôle de cohérence : une GPO par entrée de manifeste, nom et identifiant uniques
$doublons = @($manifeste | Group-Object Identifiant | Where-Object Count -gt 1)
if ($doublons.Count -gt 0) {
    Write-Warning ("Identifiants de GPO en doublon dans le manifeste : {0}" -f `
        (($doublons | ForEach-Object { $_.Name }) -join ', '))
}
if ($manifeste.Count -ne $gpos.Count) {
    Write-Warning ("Écart d'inventaire : {0} GPO lues, {1} entrées de manifeste" -f $gpos.Count, $manifeste.Count)
}

Write-Verbose "Manifeste écrit : $cheminManifeste"

# --- Compression -------------------------------------------------------------

$archive = $null
if ($Compresser) {
    $archive = "$dossier.zip"
    if ($PSCmdlet.ShouldProcess($archive, "Compression de la sauvegarde GPO")) {
        try {
            Compress-Archive -Path (Join-Path $dossier '*') -DestinationPath $archive -CompressionLevel Optimal -Force
            Write-Host ""
            Write-Host ("Archive créée : {0} ({1:N1} Mo)" -f $archive, ((Get-Item $archive).Length / 1MB)) -ForegroundColor Cyan
        }
        catch {
            Write-Warning "Compression impossible : $($_.Exception.Message)"
            $archive = $null
        }
    }
}

# --- Purge des anciennes sauvegardes ----------------------------------------

$nbPurges = 0
if ($RetentionJours -gt 0) {

    $limite = (Get-Date).AddDays(-$RetentionJours)
    Write-Host ""
    Write-Host ("Purge des sauvegardes antérieures au {0} (rétention {1} jours)" -f `
        $limite.ToString('dd/MM/yyyy'), $RetentionJours)

    $anciennes = @(Get-ChildItem -Path $CheminSauvegarde -Filter 'GPO_Backup_*' |
        Where-Object {
            $_.LastWriteTime -lt $limite -and
            $_.FullName -ne $dossier -and
            ($_.FullName -ne $archive)
        } |
        Sort-Object LastWriteTime)

    if ($anciennes.Count -eq 0) {
        Write-Host "  Aucune sauvegarde à purger." -ForegroundColor Gray
    }

    foreach ($ancienne in $anciennes) {
        if ($PSCmdlet.ShouldProcess($ancienne.FullName, "Suppression (sauvegarde de plus de $RetentionJours jours)")) {
            try {
                Remove-Item -Path $ancienne.FullName -Recurse -Force
                $nbPurges++
                Write-Host ("  [PURGE] {0}" -f $ancienne.Name) -ForegroundColor DarkGray
            }
            catch {
                Write-Warning ("  [ECHEC] Purge de {0} : {1}" -f $ancienne.Name, $_.Exception.Message)
            }
        }
    }
}

# --- Bilan -------------------------------------------------------------------

Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  GPO dans l'annuaire        : {0}" -f $gpos.Count)
Write-Host ("  Sauvegardées et vérifiées  : {0}" -f $nbOk) -ForegroundColor $(if ($nbOk -eq $gpos.Count) { 'Green' } else { 'Gray' })
Write-Host ("  Non vérifiées              : {0}" -f $nbNonVerifiees) -ForegroundColor $(if ($nbNonVerifiees) { 'Yellow' } else { 'Gray' })
Write-Host ("  Échecs                     : {0}" -f $nbEchecs) -ForegroundColor $(if ($nbEchecs) { 'Red' } else { 'Gray' })
if ($RetentionJours -gt 0) {
    Write-Host ("  Sauvegardes purgées        : {0}" -f $nbPurges) -ForegroundColor DarkGray
}
Write-Host ("  Dossier de sauvegarde      : {0}" -f $dossier) -ForegroundColor Cyan
Write-Host ("  Manifeste                  : {0}" -f $cheminManifeste) -ForegroundColor Cyan

# Sortie exploitable dans un pipeline ou un rapport de supervision
$manifeste

if ($nbOk -eq 0) { exit 2 }
if ($nbEchecs -gt 0 -or $nbNonVerifiees -gt 0) { exit 1 }
exit 0
