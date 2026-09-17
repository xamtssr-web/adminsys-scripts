<#
.SYNOPSIS
    Rapport des comptes Active Directory dont le mot de passe approche de l'expiration.

.DESCRIPTION
    Balaye les comptes utilisateurs du domaine et calcule, pour chacun, la date
    d'expiration de son mot de passe à partir de la stratégie réellement
    appliquée :

      - la stratégie par défaut du domaine (Get-ADDefaultDomainPasswordPolicy) ;
      - les stratégies granulaires de mot de passe (Fine Grained Password
        Policy / PSO) lorsqu'un objet de stratégie s'applique au compte.

    Les comptes dont le mot de passe n'expire jamais sont isolés dans une
    catégorie « SansExpiration » : ils ne doivent pas noyer le rapport, mais
    leur présence est un point d'audit à part entière.

    Le tri est fait par urgence : un mot de passe déjà expiré arrive en premier,
    puis les plus proches de l'échéance. La sortie est un objet par compte,
    exploitable directement dans un pipeline (filtrage, export, supervision).

.PARAMETER Jours
    Fenêtre d'alerte en jours (défaut : 14). Les comptes dont l'expiration tombe
    dans cette fenêtre sont listés.

.PARAMETER OU
    Restreint l'analyse à une OU et à ses sous-OU. Accepte un nom d'OU
    (« Utilisateurs ») ou un DN complet
    (« OU=Utilisateurs,DC=exemple,DC=lab »).

.PARAMETER Serveur
    Contrôleur de domaine à interroger (défaut : le contrôleur en cours).

.PARAMETER ExporterCsv
    Chemin d'export du rapport au format CSV (séparateur point-virgule, encodage
    UTF-8, lisible directement dans Excel en français).

.PARAMETER InclureSansExpiration
    Ajoute à la sortie les comptes dont le mot de passe n'expire jamais, avec
    leur source de stratégie, pour revue dans le cadre d'un audit.

.EXAMPLE
    .\Get-PasswordExpiryReport.ps1

    Rapport sur les 14 prochains jours pour l'ensemble du domaine.

.EXAMPLE
    .\Get-PasswordExpiryReport.ps1 -Jours 30 -ExporterCsv .\expiration-ad.csv

    Fenêtre d'un mois, exporté pour transmission à l'équipe support.

.EXAMPLE
    .\Get-PasswordExpiryReport.ps1 -Jours 7 -OU 'OU=Direction,DC=exemple,DC=lab' |
        Where-Object JoursRestants -le 3

    Ne garde que les cas les plus urgents d'une OU.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT), droits de lecture sur le domaine
    Version     : 1.0
    Codes retour: 0 = aucun mot de passe n'expire dans la fenêtre,
                  1 = au moins un mot de passe expire dans la fenêtre,
                  2 = au moins un mot de passe déjà expiré (ou annuaire illisible)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$Jours = 14,

    [Parameter(Mandatory = $false)]
    [string]$OU,

    [Parameter(Mandatory = $false)]
    [string]$Serveur,

    [Parameter(Mandatory = $false)]
    [string]$ExporterCsv,

    [Parameter(Mandatory = $false)]
    [switch]$InclureSansExpiration
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Chargement du module Active Directory ----------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "[ERREUR] Le module ActiveDirectory est introuvable." -ForegroundColor Red
    Write-Host "         Installez les outils RSAT :" -ForegroundColor Red
    Write-Host "         Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor DarkGray
    Write-Host "         Détail : $($_.Exception.Message)" -ForegroundColor DarkGray
    exit 2
}

$parametresAD = @{}
if ($Serveur) { $parametresAD['Server'] = $Serveur }

# --- Fonctions internes ------------------------------------------------------

function Resolve-OUCible {
    <# Accepte un nom d'OU ou un DN et renvoie le DN complet.
       Évite à l'appelant de connaître le format exact attendu par -SearchBase. #>
    param([Parameter(Mandatory = $true)][string]$Valeur)

    $ou = Get-ADOrganizationalUnit -Filter * -Properties Name @parametresAD |
        Where-Object { $_.DistinguishedName -eq $Valeur -or $_.Name -eq $Valeur } |
        Select-Object -First 1

    if (-not $ou) { throw "OU introuvable dans l'annuaire : $Valeur" }
    return $ou.DistinguishedName
}

# --- Stratégie de mot de passe de référence ----------------------------------

try {
    $strategieDefaut = Get-ADDefaultDomainPasswordPolicy @parametresAD
}
catch {
    Write-Host "[ERREUR] Lecture de la stratégie de mot de passe impossible : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

$maxAgeDefaut = if ($strategieDefaut.MaxPasswordAge) { $strategieDefaut.MaxPasswordAge.TotalDays } else { 0 }
if ($maxAgeDefaut -le 0) {
    Write-Warning "La stratégie par défaut du domaine n'impose AUCUNE expiration de mot de passe."
}

Write-Verbose ("Stratégie du domaine : expiration = {0} jour(s), longueur minimale = {1}" -f `
    $maxAgeDefaut, $strategieDefaut.MinPasswordLength)

# Stratégies granulaires : on construit une correspondance sujet (utilisateur ou
# groupe) -> objet de stratégie, en respectant l'ordre de priorité (Precedence).
$mapStrategies = @{}
try {
    $strategiesGranulaires = @(Get-ADFineGrainedPasswordPolicy -Filter * `
        -Properties AppliesTo, Precedence, MaxPasswordAge, MinPasswordLength @parametresAD |
        Sort-Object Precedence)

    foreach ($strategie in $strategiesGranulaires) {
        foreach ($sujet in @($strategie.AppliesTo)) {
            if ($sujet -and -not $mapStrategies.ContainsKey($sujet)) {
                $mapStrategies[$sujet] = $strategie
            }
        }
    }
    Write-Verbose ("{0} stratégie(s) granulaire(s) chargée(s)" -f $strategiesGranulaires.Count)
}
catch {
    Write-Verbose "Stratégies granulaires illisibles (droits insuffisants ?) : $($_.Exception.Message)"
}

# --- Recherche des comptes ---------------------------------------------------

$parametresRecherche = @{
    Filter     = '*'
    Properties = @('PasswordLastSet', 'PasswordNeverExpires', 'LastLogonDate',
        'Department', 'mail', 'whenCreated', 'DistinguishedName')
}

if ($OU) {
    try {
        $parametresRecherche['SearchBase'] = Resolve-OUCible -Valeur $OU
        $parametresRecherche['SearchScope'] = 'Subtree'
        Write-Verbose "Recherche restreinte à : $($parametresRecherche['SearchBase'])"
    }
    catch {
        Write-Host "[ERREUR] $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
}

$parametresRecherche += $parametresAD

try {
    $utilisateurs = @(Get-ADUser @parametresRecherche | Where-Object { $_.Enabled })
}
catch {
    Write-Host "[ERREUR] Interrogation de l'annuaire impossible : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

Write-Host ""
Write-Host ("Analyse de {0} compte(s) activé(s) — fenêtre d'alerte : {1} jour(s)" -f `
    $utilisateurs.Count, $Jours) -ForegroundColor White
Write-Host ("Stratégie par défaut : expiration à {0} jour(s)" -f $maxAgeDefaut)

# --- Calcul de l'expiration --------------------------------------------------

$maintenant = Get-Date
$rapport = [System.Collections.Generic.List[object]]::new()
$nbExpires = 0
$nbProches = 0
$nbSansExpiration = 0

foreach ($utilisateur in $utilisateurs) {

    $sourceStrategie = 'Stratégie du domaine'
    $dureeJours = $maxAgeDefaut

    # Une stratégie granulaire applicable au compte prime sur la stratégie par défaut
    if ($mapStrategies.ContainsKey($utilisateur.DistinguishedName)) {
        $pso = $mapStrategies[$utilisateur.DistinguishedName]
        $sourceStrategie = "PSO « $($pso.Name) »"
        $dureeJours = if ($pso.MaxPasswordAge) { $pso.MaxPasswordAge.TotalDays } else { 0 }
    }

    $sansExpiration = $utilisateur.PasswordNeverExpires -or $dureeJours -le 0

    if ($sansExpiration) {
        $nbSansExpiration++
        if ($InclureSansExpiration) {
            $rapport.Add([pscustomobject]@{
                Login            = $utilisateur.SamAccountName
                NomComplet       = $utilisateur.Name
                Email            = $utilisateur.mail
                Service          = $utilisateur.Department
                Etat             = 'SansExpiration'
                JoursRestants    = $null
                DateExpiration   = $null
                DernierChangement = $utilisateur.PasswordLastSet
                SourceStrategie  = $(if ($utilisateur.PasswordNeverExpires) { 'PasswordNeverExpires' } else { $sourceStrategie })
                DistinguishedName = $utilisateur.DistinguishedName
            })
        }
        continue
    }

    if (-not $utilisateur.PasswordLastSet) {
        # Compte activé sans mot de passe posé (création incomplète, migration…) :
        # le cas doit remonter, il est ingérable tel quel.
        $rapport.Add([pscustomobject]@{
            Login            = $utilisateur.SamAccountName
            NomComplet       = $utilisateur.Name
            Email            = $utilisateur.mail
            Service          = $utilisateur.Department
            Etat             = 'DateInconnue'
            JoursRestants    = $null
            DateExpiration   = $null
            DernierChangement = $null
            SourceStrategie  = $sourceStrategie
            DistinguishedName = $utilisateur.DistinguishedName
        })
        continue
    }

    $expiration = $utilisateur.PasswordLastSet.AddDays($dureeJours)
    $joursRestants = [math]::Floor(($expiration - $maintenant).TotalDays)

    if ($joursRestants -lt 0) {
        $etat = 'Expire'
        $nbExpires++
    }
    elseif ($joursRestants -le $Jours) {
        $etat = 'Expire bientot'
        $nbProches++
    }
    else {
        # Hors fenêtre : on ne pollue pas le rapport par défaut
        continue
    }

    $rapport.Add([pscustomobject]@{
        Login            = $utilisateur.SamAccountName
        NomComplet       = $utilisateur.Name
        Email            = $utilisateur.mail
        Service          = $utilisateur.Department
        Etat             = $etat
        JoursRestants    = [int]$joursRestants
        DateExpiration   = $expiration
        DernierChangement = $utilisateur.PasswordLastSet
        SourceStrategie  = $sourceStrategie
        DistinguishedName = $utilisateur.DistinguishedName
    })
}

# Tri par urgence : expiré d'abord, puis échéance la plus proche.
# Les entrées sans jours restants calculables terminent en fin de liste.
$sortie = @($rapport | Sort-Object -Property @{
    Expression = {
        if ($null -eq $_.JoursRestants) { [double]::MaxValue }
        elseif ($_.JoursRestants -lt 0) { [double]$_.JoursRestants }
        else { [double]$_.JoursRestants }
    }
})

# --- Affichage ---------------------------------------------------------------

if ($sortie.Count -eq 0) {
    Write-Host ""
    Write-Host "Aucun compte concerné." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host ("{0,-20} {1,-28} {2,-14} {3,7}  {4}" -f 'LOGIN', 'NOM', 'ÉTAT', 'JOURS', 'EXPIRATION') `
        -ForegroundColor White

    foreach ($ligne in $sortie) {
        $couleur = switch ($ligne.Etat) {
            'Expire'        { 'Red' }
            'Expire bientot' { 'Yellow' }
            'DateInconnue'  { 'DarkYellow' }
            default         { 'Gray' }
        }
        $jours = if ($null -eq $ligne.JoursRestants) { 'n/d' } else { "$($ligne.JoursRestants)" }
        $dateExp = if ($ligne.DateExpiration) { $ligne.DateExpiration.ToString('dd/MM/yyyy HH:mm') } else { '-' }

        Write-Host ("{0,-20} {1,-28} {2,-14} {3,7}  {4}" -f `
            $ligne.Login, $ligne.NomComplet, $ligne.Etat, $jours, $dateExp) -ForegroundColor $couleur
    }
}

# --- Bilan -------------------------------------------------------------------

$nbDateInconnue = @($sortie | Where-Object Etat -eq 'DateInconnue').Count

Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  Fenêtre analysée          : {0} jour(s)" -f $Jours)
Write-Host ("  Déjà expirés              : {0}" -f $nbExpires) -ForegroundColor $(if ($nbExpires) { 'Red' } else { 'Gray' })
Write-Host ("  Expirent dans la fenêtre  : {0}" -f $nbProches) -ForegroundColor $(if ($nbProches) { 'Yellow' } else { 'Gray' })
Write-Host ("  Date de changement absente: {0}" -f $nbDateInconnue) -ForegroundColor $(if ($nbDateInconnue) { 'DarkYellow' } else { 'Gray' })
if ($InclureSansExpiration) {
    Write-Host ("  Sans expiration (PME/PSO) : {0}" -f $nbSansExpiration) -ForegroundColor DarkGray
}

if ($ExporterCsv) {
    $sortie | Export-Csv -Path $ExporterCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
    Write-Host ""
    Write-Host ("Rapport exporté vers {0}" -f $ExporterCsv) -ForegroundColor Cyan
}

# Sortie exploitable dans un pipeline
$sortie

if ($nbExpires -gt 0) { exit 2 }
if ($nbProches -gt 0) { exit 1 }
exit 0
