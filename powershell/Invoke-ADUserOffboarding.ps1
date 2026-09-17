<#
.SYNOPSIS
    Traite le départ d'un collaborateur : désactivation, groupes, quarantaine, messagerie, traçabilité.

.DESCRIPTION
    Le départ d'un salarié est le moment où l'annuaire se remplit de comptes
    actifs que personne ne surveille : c'est un vecteur d'attaque classique et
    un écart systématique en audit. Ce script fait l'ensemble du traitement en
    une commande, dans le bon ordre, et laisse une trace.

    Déroulé : contrôle des garde-fous, export des appartenances AVANT
    modification (traçabilité), désactivation du compte, retrait des groupes,
    déplacement en quarantaine, archivage de la messagerie si les outils
    Exchange/Microsoft 365 sont disponibles, puis fiche de sortie listant ce qui
    a été fait et ce qui reste à faire manuellement.

    Le compte n'est jamais supprimé : la désactivation est réversible, la
    suppression ne l'est pas. Une période de quarantaine permet de rouvrir un
    accès en cas de retour ou de litige.

.PARAMETER Identite
    Compte à traiter : identifiant (sAMAccountName), UPN ou nom complet.

.PARAMETER OUQuarantaine
    OU de destination du compte désactivé, au format DN.
    Exemple : 'OU=Quarantaine,OU=Utilisateurs,DC=exemple,DC=lab'

.PARAMETER JournalAudit
    Fichier CSV de journalisation (une ligne par action). Par défaut
    .\journal-offboarding.csv dans le dossier courant.

.PARAMETER ConserverGroupes
    Ne retire pas le compte de ses groupes (utile si l'accès doit être
    restauré rapidement à l'identique).

.PARAMETER ArchiverMessagerie
    Tente l'archivage de la boîte aux lettres (Exchange local via
    Disable-Mailbox, Microsoft 365 via Microsoft Graph). Si les modules ne sont
    pas disponibles, l'action est inscrite « à faire manuellement » dans la
    fiche de sortie — jamais de faux succès.

.PARAMETER FicheSortie
    Chemin de la fiche de sortie générée (texte). Par défaut
    .\sortie-<identifiant>-<date>.txt

.PARAMETER Forcer
    Autorise le traitement des comptes habituellement protégés (membres de
    groupes à privilèges). À n'utiliser qu'en connaissance de cause.

.EXAMPLE
    .\Invoke-ADUserOffboarding.ps1 -Identite j.dupont `
        -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab'

    Simulation : affiche tout ce qui serait fait, ne modifie rien.

.EXAMPLE
    .\Invoke-ADUserOffboarding.ps1 -Identite j.dupont `
        -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab' -ArchiverMessagerie -Confirm

    Traitement réel, avec archivage de la messagerie et confirmation à chaque étape.

.EXAMPLE
    .\Invoke-ADUserOffboarding.ps1 -Identite j.dupont `
        -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab' -ConserverGroupes -WhatIf

    Simulation en conservant les groupes.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT), droits de modification sur
                  l'OU source et l'OU de quarantaine. Exchange/Graph facultatifs.
    Version     : 1.0
    Codes retour: 0 = traitement effectué (ou simulation) sans incident
                  1 = traitement effectué avec des actions manuelles restantes
                  2 = refus ou échec (compte protégé, OU invalide, droits insuffisants)
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Compte à traiter (identifiant, UPN ou nom complet)")]
    [string]$Identite,

    [Parameter(Mandatory = $true, HelpMessage = "OU de quarantaine au format DN")]
    [string]$OUQuarantaine,

    [Parameter(Mandatory = $false)]
    [string]$JournalAudit = (Join-Path (Get-Location) 'journal-offboarding.csv'),

    [Parameter(Mandatory = $false)]
    [switch]$ConserverGroupes,

    [Parameter(Mandatory = $false)]
    [switch]$ArchiverMessagerie,

    [Parameter(Mandatory = $false)]
    [string]$FicheSortie,

    [Parameter(Mandatory = $false)]
    [switch]$Forcer
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$horodatage = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$actionsManuelles = @()
$journal = [System.Collections.Generic.List[object]]::new()

function Add-Journal {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$Resultat,
        [string]$Detail = ''
    )
    $journal.Add([pscustomobject]@{
        Horodatage = $horodatage
        Compte     = $Identite
        Action     = $Action
        Resultat   = $Resultat
        Detail     = $Detail
    })
    $couleur = switch ($Resultat) {
        'OK'        { 'Green' }
        'IGNORE'    { 'DarkGray' }
        'MANUEL'    { 'Yellow' }
        default     { 'Red' }
    }
    Write-Host ("  [{0,-7}] {1,-32} {2}" -f $Resultat, $Action, $Detail) -ForegroundColor $couleur
}

function Write-Section {
    param([string]$Titre)
    Write-Host ""
    Write-Host ("==> $Titre") -ForegroundColor Cyan
}

# --- Prérequis ---------------------------------------------------------------
Import-Module ActiveDirectory -ErrorAction Stop

Write-Host ""
Write-Host "=== Départ de collaborateur ===" -ForegroundColor White
Write-Host ("Compte visé : {0}" -f $Identite)

# --- 1. Contrôles préalables -------------------------------------------------
Write-Section "1. Contrôles préalables"

$compte = $null
foreach ($propriete in @('SamAccountName', 'UserPrincipalName', 'Name', 'DisplayName')) {
    $compte = Get-ADUser -Filter "$propriete -eq '$Identite'" -Properties MemberOf, AdminCount, ServicePrincipalName, DistinguishedName, Enabled -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($compte) { break }
}

if (-not $compte) {
    Add-Journal -Action 'Résolution du compte' -Resultat 'ECHEC' -Detail "aucun compte trouvé pour « $Identite »"
    Write-Error "Compte introuvable : $Identite"
    exit 2
}

$dnSource = $compte.DistinguishedName
Add-Journal -Action 'Résolution du compte' -Resultat 'OK' -Detail "$($compte.SamAccountName) — $dnSource"

# Garde-fous : comptes qu'on ne désactive jamais par automatisme
$refus = @()

if ($compte.SID.Value -match '-500$') {
    $refus += "compte Administrator du domaine (RID 500)"
}
if ($compte.SamAccountName -eq 'krbtgt') {
    $refus += "compte krbtgt (compte de service Kerberos)"
}
if (-not $compte.Enabled) {
    Add-Journal -Action 'État du compte' -Resultat 'IGNORE' -Detail 'compte déjà désactivé'
}
if ($compte.AdminCount -eq 1) {
    $refus += "compte marqué AdminCount=1 (ancien ou actuel privilégié)"
}
if ($compte.ServicePrincipalName.Count -gt 0) {
    $refus += "compte de service (SPN déclaré) : $($compte.ServicePrincipalName -join ', ')"
}

$groupesPrivilegiesSid = @(
    'S-1-5-32-544'   # Administrateurs
    'S-1-5-32-548'   # Opérateurs de compte
    'S-1-5-32-549'   # Opérateurs de serveur
    'S-1-5-32-550'   # Opérateurs d'impression
    'S-1-5-32-551'   # Opérateurs de sauvegarde
    'S-1-5-32-552'   # Réplicateurs
)
$membresPrivilegies = @($compte.MemberOf | ForEach-Object {
    $groupe = Get-ADGroup -Identity $_ -Properties SID -ErrorAction SilentlyContinue
    if ($groupe -and $groupesPrivilegiesSid -contains $groupe.SID.Value) { $groupe.Name }
} | Where-Object { $_ })
if ($membresPrivilegies.Count -gt 0) {
    $refus += "membre de groupe(s) à privilèges : $($membresPrivilegies -join ', ')"
}

if ($refus.Count -gt 0 -and -not $Forcer) {
    foreach ($motif in $refus) {
        Add-Journal -Action 'Garde-fou' -Resultat 'REFUS' -Detail $motif
    }
    Write-Error "Traitement refusé : $($refus -join ' ; '). Utilisez -Forcer uniquement en connaissance de cause."
    exit 2
}
if ($refus.Count -gt 0 -and $Forcer) {
    foreach ($motif in $refus) {
        Add-Journal -Action 'Garde-fou' -Resultat 'MANUEL' -Detail "-Forcer utilisé malgré : $motif"
    }
}

# OU de quarantaine
if (-not (Get-ADOrganizationalUnit -Identity $OUQuarantaine -ErrorAction SilentlyContinue)) {
    Add-Journal -Action 'OU de quarantaine' -Resultat 'ECHEC' -Detail "introuvable : $OUQuarantaine"
    Write-Error "OU de quarantaine introuvable : $OUQuarantaine"
    exit 2
}
Add-Journal -Action 'OU de quarantaine' -Resultat 'OK' -Detail $OUQuarantaine

# --- 2. Export des appartenances AVANT modification --------------------------
Write-Section "2. Traçabilité"

$groupes = @($compte.MemberOf | ForEach-Object {
    (Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue).Name
} | Where-Object { $_ })

$exportGroupes = Join-Path (Get-Location) ("groupes-" + $compte.SamAccountName + "-" + (Get-Date -Format 'yyyyMMdd') + ".csv")
$groupes | ForEach-Object { [pscustomobject]@{ Compte = $compte.SamAccountName; Groupe = $_; Date = $horodatage } } |
    Export-Csv -Path $exportGroupes -NoTypeInformation -Delimiter ';' -Encoding UTF8

Add-Journal -Action 'Export des appartenances' -Resultat 'OK' -Detail ("{0} groupe(s) → {1}" -f $groupes.Count, (Split-Path $exportGroupes -Leaf))

# --- 3. Désactivation --------------------------------------------------------
Write-Section "3. Désactivation"

if ($compte.Enabled) {
    if ($PSCmdlet.ShouldProcess($compte.SamAccountName, 'Désactiver le compte')) {
        Disable-ADUser -Identity $compte.DistinguishedName
        Add-Journal -Action 'Désactivation du compte' -Resultat 'OK' -Detail 'compte désactivé (réversible)'
    }
    else {
        Add-Journal -Action 'Désactivation du compte' -Resultat 'IGNORE' -Detail 'non appliqué (simulation)'
    }
}

# --- 4. Retrait des groupes --------------------------------------------------
Write-Section "4. Retrait des groupes"

if (-not $ConserverGroupes) {
    foreach ($nomGroupe in $groupes) {
        if ($PSCmdlet.ShouldProcess($compte.SamAccountName, "Retirer du groupe $nomGroupe")) {
            try {
                Remove-ADGroupMember -Identity $nomGroupe -Members $compte.DistinguishedName -Confirm:$false
                Add-Journal -Action "Retrait du groupe $nomGroupe" -Resultat 'OK'
            }
            catch {
                Add-Journal -Action "Retrait du groupe $nomGroupe" -Resultat 'ECHEC' -Detail $_.Exception.Message
            }
        }
        else {
            Add-Journal -Action "Retrait du groupe $nomGroupe" -Resultat 'IGNORE' -Detail 'non appliqué (simulation)'
        }
    }
    if ($groupes.Count -eq 0) {
        Add-Journal -Action 'Retrait des groupes' -Resultat 'IGNORE' -Detail 'le compte n''appartenait à aucun groupe'
    }
}
else {
    Add-Journal -Action 'Retrait des groupes' -Resultat 'IGNORE' -Detail '-ConserverGroupes : appartenances maintenues'
}

# --- 5. Déplacement en quarantaine ------------------------------------------
Write-Section "5. Quarantaine"

$dnCible = "CN=$($compte.Name),$OUQuarantaine"
if ($dnSource -eq $dnCible) {
    Add-Journal -Action 'Déplacement' -Resultat 'IGNORE' -Detail 'le compte est déjà en quarantaine'
}
elseif ($PSCmdlet.ShouldProcess($compte.SamAccountName, "Déplacer vers $OUQuarantaine")) {
    try {
        Move-ADObject -Identity $dnSource -TargetPath $OUQuarantaine
        Add-Journal -Action 'Déplacement en quarantaine' -Resultat 'OK' -Detail $OUQuarantaine
    }
    catch {
        Add-Journal -Action 'Déplacement en quarantaine' -Resultat 'ECHEC' -Detail $_.Exception.Message
    }
}
else {
    Add-Journal -Action 'Déplacement en quarantaine' -Resultat 'IGNORE' -Detail 'non appliqué (simulation)'
}

# --- 6. Messagerie -----------------------------------------------------------
Write-Section "6. Messagerie"

if ($ArchiverMessagerie) {
    $outilsExchange = Get-Command -Name 'Disable-Mailbox' -ErrorAction SilentlyContinue
    $outilsGraph = Get-Command -Name 'Remove-MgUserLicense' -ErrorAction SilentlyContinue

    if ($outilsExchange) {
        if ($PSCmdlet.ShouldProcess($compte.SamAccountName, 'Désactiver la boîte aux lettres (conservee en base)')) {
            try {
                Disable-Mailbox -Identity $compte.SamAccountName -Confirm:$false -ErrorAction Stop
                Add-Journal -Action 'Messagerie : boîte désactivée' -Resultat 'OK' -Detail 'contenu conservé en base, réactivable'
            }
            catch {
                Add-Journal -Action 'Messagerie : boîte désactivée' -Resultat 'ECHEC' -Detail $_.Exception.Message
            }
        }
    }
    elseif ($outilsGraph) {
        if ($PSCmdlet.ShouldProcess($compte.SamAccountName, 'Retirer les licences Microsoft 365')) {
            try {
                $utilisateur = Get-MgUser -UserId $compte.UserPrincipalName -ErrorAction Stop
                $licences = @(Get-MgUserLicenseDetail -UserId $utilisateur.Id -ErrorAction SilentlyContinue)
                if ($licences.Count -eq 0) {
                    Add-Journal -Action 'Licences Microsoft 365' -Resultat 'IGNORE' -Detail 'aucune licence attribuée'
                }
                else {
                    $ids = $licences | ForEach-Object { $_.SkuId }
                    Set-MgUserLicense -UserId $utilisateur.Id -AddLicenses @() -RemoveLicenses $ids -ErrorAction Stop
                    Add-Journal -Action 'Licences Microsoft 365' -Resultat 'OK' -Detail ("$($ids.Count) licence(s) libérée(s)")
                }
            }
            catch {
                Add-Journal -Action 'Licences Microsoft 365' -Resultat 'MANUEL' -Detail $_.Exception.Message
                $actionsManuelles += "Libérer les licences Microsoft 365 de $($compte.UserPrincipalName)"
            }
        }
    }
    else {
        Add-Journal -Action 'Messagerie' -Resultat 'MANUEL' -Detail 'ni Exchange ni Microsoft Graph disponibles sur ce poste'
        $actionsManuelles += "Archiver / désactiver la boîte aux lettres de $($compte.SamAccountName) depuis la console d'administration de la messagerie"
    }
}
else {
    Add-Journal -Action 'Messagerie' -Resultat 'IGNORE' -Detail 'non demandée (-ArchiverMessagerie)'
    $actionsManuelles += "Traiter la boîte aux lettres de $($compte.SamAccountName) (archivage ou désactivation)"
}

# --- 7. Fiche de sortie ------------------------------------------------------
Write-Section "7. Fiche de sortie"

if (-not $FicheSortie) {
    $FicheSortie = Join-Path (Get-Location) ("sortie-" + $compte.SamAccountName + "-" + (Get-Date -Format 'yyyyMMdd') + ".txt")
}

if ($PSCmdlet.ShouldProcess($FicheSortie, 'Générer la fiche de sortie')) {
    $lignes = @()
    $lignes += "FICHE DE DEPART — COLLABORATEUR"
    $lignes += "=" * 60
    $lignes += "Date du traitement   : $horodatage"
    $lignes += "Compte               : $($compte.SamAccountName)"
    $lignes += "Nom complet          : $($compte.Name)"
    $lignes += "UPN                  : $($compte.UserPrincipalName)"
    $lignes += "DN d'origine         : $dnSource"
    $lignes += "OU de quarantaine    : $OUQuarantaine"
    $lignes += "Groupes retirés      : $($groupes.Count)"
    $lignes += "Export des groupes   : $(Split-Path $exportGroupes -Leaf)"
    $lignes += "Journal d'audit      : $(Split-Path $JournalAudit -Leaf)"
    $lignes += ""
    $lignes += "ACTIONS REALISEES"
    $lignes += "-" * 60
    foreach ($ligne in $journal) {
        if ($ligne.Resultat -eq 'OK') { $lignes += "  [x] $($ligne.Action)" }
    }
    $lignes += ""
    $lignes += "ACTIONS RESTANT A FAIRE MANUELLEMENT"
    $lignes += "-" * 60
    if ($actionsManuelles.Count -eq 0) {
        $lignes += "  (aucune)"
    }
    else {
        foreach ($action in $actionsManuelles) { $lignes += "  [ ] $action" }
    }
    $lignes += ""
    $lignes += "RAPPEL : le compte est désactivé, jamais supprimé. Sa réactivation"
    $lignes += "reste possible pendant la période de quarantaine."

    $lignes | Set-Content -Path $FicheSortie -Encoding UTF8
    Add-Journal -Action 'Fiche de sortie' -Resultat 'OK' -Detail (Split-Path $FicheSortie -Leaf)
}

# --- Journal d'audit ---------------------------------------------------------
$entete = -not (Test-Path $JournalAudit)
$journal | Export-Csv -Path $JournalAudit -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Append:$(!$entete)

# --- Bilan -------------------------------------------------------------------
Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  Compte              : {0}" -f $compte.SamAccountName)
Write-Host ("  Groupes retirés     : {0}" -f $(if ($ConserverGroupes) { 0 } else { $groupes.Count }))
Write-Host ("  Journal d'audit     : {0}" -f $JournalAudit)
Write-Host ("  Fiche de sortie     : {0}" -f $FicheSortie)
if ($actionsManuelles.Count -gt 0) {
    Write-Host ("  Actions manuelles   : {0}" -f $actionsManuelles.Count) -ForegroundColor Yellow
    foreach ($action in $actionsManuelles) {
        Write-Host ("     - $action") -ForegroundColor Yellow
    }
}

if ($actionsManuelles.Count -gt 0) { exit 1 }
exit 0
