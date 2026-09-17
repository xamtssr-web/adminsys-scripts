<#
.SYNOPSIS
    Contrôle de santé complet d'un annuaire Active Directory.

.DESCRIPTION
    Regroupe en un seul rapport les vérifications qu'un administrateur fait
    à la main après une alerte : réplication entre contrôleurs, rôles FSMO,
    services critiques, espace disque de SYSVOL et de la base NTDS,
    cohérence DNS, comptes à mot de passe expiré ou désactivés, et
    vérification des sauvegardes système (tombstone).

    Chaque contrôle renvoie un objet avec un statut OK / ATTENTION / CRITIQUE,
    ce qui permet de l'intégrer à une supervision existante (Zabbix, Centreon)
    ou de le planifier avec une tâche pour recevoir une alerte par mail.

.PARAMETER Serveur
    Contrôleur de domaine à interroger (défaut : le DC en cours).

.PARAMETER SeuilDisquePourcent
    Seuil d'alerte d'occupation disque (défaut : 80).

.PARAMETER JoursMotDePasse
    Fenêtre d'alerte pour les mots de passe arrivant à expiration (défaut : 14).

.PARAMETER ExporterCsv
    Chemin d'export du rapport détaillé au format CSV.

.EXAMPLE
    .\Get-ADHealthReport.ps1

    Rapport de santé sur le DC courant, affiché en couleur.

.EXAMPLE
    .\Get-ADHealthReport.ps1 -Serveur DC02 -ExporterCsv .\sante-ad.csv -JoursMotDePasse 7

    Rapport sur DC02, exporté pour archivage.

.EXAMPLE
    .\Get-ADHealthReport.ps1 | Where-Object Statut -ne 'OK'

    N'affiche que les points problématiques — à mettre dans un script planifié.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT), droits de lecture sur le domaine
    Version     : 1.0
    Codes retour: 0 = tout est OK, 1 = au moins un avertissement, 2 = au moins un point critique
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Serveur,

    [Parameter(Mandatory = $false)]
    [ValidateRange(50, 99)]
    [int]$SeuilDisquePourcent = 80,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$JoursMotDePasse = 14,

    [Parameter(Mandatory = $false)]
    [string]$ExporterCsv
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Infrastructure du rapport ----------------------------------------------
$rapport = [System.Collections.Generic.List[object]]::new()

function Add-Controle {
    <# Enregistre un résultat de contrôle et l'affiche immédiatement. #>
    param(
        [Parameter(Mandatory = $true)][string]$Categorie,
        [Parameter(Mandatory = $true)][string]$Controle,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'ATTENTION', 'CRITIQUE', 'INCONNU')][string]$Statut,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $couleur = switch ($Statut) {
        'OK'        { 'Green' }
        'ATTENTION' { 'Yellow' }
        'CRITIQUE'  { 'Red' }
        default     { 'Gray' }
    }

    Write-Host ("  [{0,-9}] {1,-38} {2}" -f $Statut, $Controle, $Detail) -ForegroundColor $couleur

    $rapport.Add([pscustomobject]@{
        Categorie = $Categorie
        Controle  = $Controle
        Statut    = $Statut
        Detail    = $Detail
        Date      = (Get-Date)
    })
}

function Write-Section {
    param([string]$Titre)
    Write-Host ""
    Write-Host ("==> $Titre") -ForegroundColor Cyan
}

# --- Prérequis ---------------------------------------------------------------
Import-Module ActiveDirectory -ErrorAction Stop

$parametresAD = @{}
if ($Serveur) { $parametresAD['Server'] = $Serveur }

$domaine = Get-ADDomain @parametresAD
$foret = Get-ADForest @parametresAD

Write-Host ""
Write-Host ("Rapport de santé Active Directory — {0}" -f $foret.Name) -ForegroundColor White

# --- 1. Services critiques ---------------------------------------------------
Write-Section "Services critiques du contrôleur"

$servicesRequis = @{
    'NTDS'    = 'Annuaire (base de données)'
    'DNS'     = 'Résolution de noms'
    'Netlogon'= 'Authentification machine'
    'DFSR'    = 'Réplication SYSVOL'
    'W32Time' = 'Synchronisation horaire'
}

foreach ($service in $servicesRequis.Keys) {
    $objet = Get-Service -Name $service -ErrorAction SilentlyContinue
    if (-not $objet) {
        Add-Controle -Categorie 'Services' -Controle "Service $service" -Statut 'CRITIQUE' `
            -Detail "service absent ($($servicesRequis[$service]))"
    }
    elseif ($objet.Status -eq 'Running') {
        Add-Controle -Categorie 'Services' -Controle "Service $service" -Statut 'OK' `
            -Detail "$($servicesRequis[$service]) — démarré"
    }
    else {
        Add-Controle -Categorie 'Services' -Controle "Service $service" -Statut 'CRITIQUE' `
            -Detail "$($servicesRequis[$service]) — état : $($objet.Status)"
    }
}

# --- 2. Réplication entre contrôleurs ---------------------------------------
Write-Section "Réplication entre contrôleurs de domaine"

try {
    $replications = Get-ADReplicationPartnerMetadata -Target $foret.Name -Scope Forest @parametresAD

    $enRetard = @($replications | Where-Object {
        $_.LastReplicationResult -ne 0 -or
        ($_.LastReplicationSuccess -and (New-TimeSpan -Start $_.LastReplicationSuccess).TotalHours -gt 24)
    })

    if ($enRetard.Count -eq 0) {
        Add-Controle -Categorie 'Réplication' -Controle 'État de la réplication' -Statut 'OK' `
            -Detail "$($replications.Count) partenaire(s) répliqué(s) sans erreur"
    }
    else {
        foreach ($partenaire in $enRetard) {
            Add-Controle -Categorie 'Réplication' -Controle "Partenaire $($partenaire.Partner)" -Statut 'CRITIQUE' `
                -Detail "dernier succès : $($partenaire.LastReplicationSuccess), code $($partenaire.LastReplicationResult)"
        }
    }
}
catch {
    Add-Controle -Categorie 'Réplication' -Controle 'État de la réplication' -Statut 'INCONNU' `
        -Detail "impossible d'interroger la réplication : $($_.Exception.Message)"
}

# --- 3. Rôles FSMO -----------------------------------------------------------
Write-Section "Rôles opérationnels (FSMO)"

$rolesFSMO = [ordered]@{
    'PDCEmulator'   = $domaine.PDCEmulator
    'RIDMaster'     = $domaine.RIDMaster
    'InfrastructureMaster' = $domaine.InfrastructureMaster
    'SchemaMaster'  = $foret.SchemaMaster
    'DomainNamingMaster' = $foret.DomainNamingMaster
}

foreach ($role in $rolesFSMO.Keys) {
    $porteur = $rolesFSMO[$role]
    $joignable = $null -ne (Get-ADDomainController -Identity $porteur -ErrorAction SilentlyContinue)
    $statut = if ($joignable) { 'OK' } else { 'CRITIQUE' }
    $detail = if ($joignable) { "porté par $porteur" } else { "porteur $porteur INJOIGNABLE" }
    Add-Controle -Categorie 'FSMO' -Controle $role -Statut $statut -Detail $detail
}

# --- 4. Espace disque -------------------------------------------------------
Write-Section "Espace disque (base NTDS et SYSVOL)"

$cheminNTDS = Join-Path $env:SystemRoot 'NTDS'
$cheminSYSVOL = Join-Path $env:SystemRoot 'SYSVOL'

foreach ($chemin in @($cheminNTDS, $cheminSYSVOL)) {
    if (-not (Test-Path $chemin)) {
        Add-Controle -Categorie 'Stockage' -Controle (Split-Path $chemin -Leaf) -Statut 'INCONNU' `
            -Detail "$chemin introuvable sur cet hôte"
        continue
    }

    $lettre = (Get-Item $chemin).PSDrive.Name
    $disque = Get-PSDrive -Name $lettre -ErrorAction SilentlyContinue
    if ($disque -and $disque.Used -ne $null) {
        $total = $disque.Used + $disque.Free
        $pourcent = if ($total -gt 0) { [math]::Round(($disque.Used / $total) * 100, 0) } else { 0 }
        $statut = 'OK'
        if ($pourcent -ge $SeuilDisquePourcent) { $statut = 'ATTENTION' }
        if ($pourcent -ge 90) { $statut = 'CRITIQUE' }
        Add-Controle -Categorie 'Stockage' -Controle (Split-Path $chemin -Leaf) -Statut $statut `
            -Detail ("{0}% utilisé ({1:N1} Go libres sur {2})" -f $pourcent, ($disque.Free / 1GB), $lettre)
    }
}

# --- 5. Tombstone (fenêtre de restauration) ---------------------------------
Write-Section "Restauration et sauvegardes"

try {
    $tombstone = (Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($domaine.DistinguishedName)" `
        -Properties tombstoneLifetime @parametresAD).tombstoneLifetime

    if ($tombstone -ge 180) {
        Add-Controle -Categorie 'Sauvegarde' -Controle 'Durée de vie tombstone' -Statut 'OK' `
            -Detail "$tombstone jours de restauration possible"
    }
    else {
        Add-Controle -Categorie 'Sauvegarde' -Controle 'Durée de vie tombstone' -Statut 'ATTENTION' `
            -Detail "$tombstone jours seulement (Microsoft recommande au moins 180)"
    }
}
catch {
    Add-Controle -Categorie 'Sauvegarde' -Controle 'Durée de vie tombstone' -Statut 'INCONNU' `
        -Detail "valeur par défaut de la forêt utilisée (180 jours)"
}

# --- 6. Comptes et mots de passe --------------------------------------------
Write-Section "Comptes utilisateurs"

$tousUtilisateurs = Get-ADUser -Filter * -Properties PasswordLastSet, PasswordNeverExpires, LastLogonDate @parametresAD
$actifs = @($tousUtilisateurs | Where-Object { $_.Enabled })

Add-Controle -Categorie 'Comptes' -Controle 'Utilisateurs activés' -Statut 'OK' `
    -Detail "$($actifs.Count) compte(s) actif(s) sur $($tousUtilisateurs.Count)"

# Comptes avec mot de passe éternel : un point de contrôle classique d'audit
$motDePasseInfini = @($actifs | Where-Object { $_.PasswordNeverExpires })
$statut = if ($motDePasseInfini.Count -eq 0) { 'OK' } else { 'ATTENTION' }
Add-Controle -Categorie 'Comptes' -Controle 'Mot de passe sans expiration' -Statut $statut `
    -Detail "$($motDePasseInfini.Count) compte(s) avec mot de passe non expirant"

# Comptes jamais utilisés depuis plus de 90 jours
$seuilInactivite = (Get-Date).AddDays(-90)
$inactifs = @($actifs | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $seuilInactivite })
$statut = if ($inactifs.Count -eq 0) { 'OK' } elseif ($inactifs.Count -lt 10) { 'ATTENTION' } else { 'CRITIQUE' }
Add-Controle -Categorie 'Comptes' -Controle 'Inactifs depuis plus de 90 jours' -Statut $statut `
    -Detail "$($inactifs.Count) compte(s) — candidats à une désactivation"

# --- 7. Stratégie de mot de passe -------------------------------------------
Write-Section "Stratégie de mot de passe du domaine"

try {
    $strategie = Get-ADDefaultDomainPasswordPolicy @parametresAD

    $statut = if ($strategie.MinPasswordLength -ge 12) { 'OK' } else { 'ATTENTION' }
    Add-Controle -Categorie 'Politique' -Controle 'Longueur minimale' -Statut $statut `
        -Detail "$($strategie.MinPasswordLength) caractères (recommandé : 12 à 14)"

    $statut = if ($strategie.LockoutThreshold -gt 0) { 'OK' } else { 'CRITIQUE' }
    Add-Controle -Categorie 'Politique' -Controle 'Verrouillage de compte' -Statut $statut `
        -Detail $(if ($strategie.LockoutThreshold -gt 0) {
            "$($strategie.LockoutThreshold) tentatives, durée $($strategie.LockoutDuration)"
        } else { 'AUCUN verrouillage : attaque par dictionnaire sans limite' })

    $statut = if ($strategie.ComplexityEnabled) { 'OK' } else { 'ATTENTION' }
    Add-Controle -Categorie 'Politique' -Controle 'Complexité requise' -Statut $statut `
        -Detail $(if ($strategie.ComplexityEnabled) { 'activée' } else { 'désactivée' })
}
catch {
    Add-Controle -Categorie 'Politique' -Controle 'Stratégie par défaut' -Statut 'INCONNU' `
        -Detail $_.Exception.Message
}

# --- Bilan -------------------------------------------------------------------
$nbCritique = @($rapport | Where-Object Statut -eq 'CRITIQUE').Count
$nbAttention = @($rapport | Where-Object Statut -eq 'ATTENTION').Count
$nbOk = @($rapport | Where-Object Statut -eq 'OK').Count
$nbInconnu = @($rapport | Where-Object Statut -eq 'INCONNU').Count

Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  OK         : {0}" -f $nbOk)
Write-Host ("  ATTENTION  : {0}" -f $nbAttention) -ForegroundColor $(if ($nbAttention) { 'Yellow' } else { 'Gray' })
Write-Host ("  CRITIQUE   : {0}" -f $nbCritique) -ForegroundColor $(if ($nbCritique) { 'Red' } else { 'Gray' })
if ($nbInconnu) { Write-Host ("  NON ÉVALUÉ : {0}" -f $nbInconnu) -ForegroundColor DarkGray }

if ($ExporterCsv) {
    $rapport | Export-Csv -Path $ExporterCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
    Write-Host ("`nRapport exporté vers {0}" -f $ExporterCsv)
}

# Sortie exploitable dans un pipeline : uniquement les points à traiter
$rapport | Where-Object { $_.Statut -in @('ATTENTION', 'CRITIQUE') }

if ($nbCritique -gt 0) { exit 2 }
if ($nbAttention -gt 0) { exit 1 }
exit 0
