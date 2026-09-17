<#
.SYNOPSIS
    Audite le durcissement d'un domaine Active Directory par rapport à une base de référence.

.DESCRIPTION
    Contrôle en LECTURE SEULE (aucune modification, aucune écriture dans
    l'annuaire) les principaux réglages de sécurité d'un domaine, et renvoie une
    ligne par point de contrôle avec un statut :

      - CONFORME     : le réglage respecte la base de référence ;
      - NON CONFORME : le réglage est absent ou dangereux, correction requise ;
      - À VÉRIFIER   : lecture impossible (droits, rôle de la machine) ou valeur
                       limite à valider avec l'exploitant.

    Contrôles effectués :
      1. Longueur minimale du mot de passe du domaine ;
      2. Historique des mots de passe ;
      3. Expiration des mots de passe (aucune stratégie « sans expiration ») ;
      4. Verrouillage de compte (seuil, durée, fenêtre d'observation) ;
      5. Comptes à privilèges élevés (AdminCount = 1) et comptes à mot de passe
         non expirant parmi ceux-ci ;
      6. Membres de Domain Admins, Enterprise Admins et Administrateurs du schéma ;
      7. Comptes autorisés pour une délégation Kerberos non contrainte
         (hors contrôleurs de domaine) ;
      8. Durée de vie des tickets Kerberos (maxTicketAge) ;
      9. Source de temps (NTP) — un décalage horaire supérieur à 5 minutes casse
         Kerberos ;
     10. SMBv1 désactivé ;
     11. Signature LDAP (LDAPServerIntegrity) et liaison de canal (channel binding).

    À exécuter avec un compte de lecteur du domaine pour la partie annuaire ; les
    contrôles 9 à 11 lisent le registre de la machine locale et doivent donc être
    lancés sur chaque contrôleur de domaine pour un état complet.

.PARAMETER LongueurMinimale
    Longueur minimale de mot de passe attendue (défaut : 14 caractères).

.PARAMETER HistoriqueMinimum
    Nombre de mots de passe mémorisés attendu (défaut : 24).

.PARAMETER TentativesMax
    Nombre maximal de tentatives de connexion avant verrouillage toléré
    (défaut : 10).

.PARAMETER Serveur
    Contrôleur de domaine à interroger (défaut : le contrôleur en cours).

.PARAMETER ExporterCsv
    Chemin d'export du rapport complet au format CSV (séparateur point-virgule).

.PARAMETER ProblemesSeulement
    Ne renvoie dans le pipeline que les contrôles NON CONFORME et À VÉRIFIER.

.EXAMPLE
    .\Test-ADHardeningBaseline.ps1

    Audit complet du domaine courant, affiché en couleur.

.EXAMPLE
    .\Test-ADHardeningBaseline.ps1 -ExporterCsv .\audit-durcissement.csv -ProblemesSeulement

    Audit exporté pour le dossier de conformité, seuls les écarts sont renvoyés.

.EXAMPLE
    .\Test-ADHardeningBaseline.ps1 -LongueurMinimale 16 -HistoriqueMinimum 30 |
        Where-Object Statut -eq 'NON CONFORME'

    Base de référence renforcée, filtrée sur les seuls écarts critiques.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT) ; exécution en administrateur local
                  sur le contrôleur pour les contrôles registre (SMBv1, signature LDAP)
    Version     : 1.0
    Codes retour: 0 = tous les contrôles conformes,
                  1 = au moins un contrôle à vérifier,
                  2 = au moins un contrôle non conforme
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(8, 128)]
    [int]$LongueurMinimale = 14,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$HistoriqueMinimum = 24,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$TentativesMax = 10,

    [Parameter(Mandatory = $false)]
    [string]$Serveur,

    [Parameter(Mandatory = $false)]
    [string]$ExporterCsv,

    [Parameter(Mandatory = $false)]
    [switch]$ProblemesSeulement
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

# --- Infrastructure du rapport ----------------------------------------------

$rapport = [System.Collections.Generic.List[object]]::new()

function Add-Controle {
    <# Enregistre et affiche un résultat de contrôle.
       La sortie est un objet PSCustomObject : une ligne par contrôle, directement
       exploitable dans un CSV de conformité ou une supervision. #>
    param(
        [Parameter(Mandatory = $true)][string]$Categorie,
        [Parameter(Mandatory = $true)][string]$Controle,
        [Parameter(Mandatory = $true)]
        [ValidateSet('CONFORME', 'NON CONFORME', 'À VÉRIFIER')][string]$Statut,
        [Parameter(Mandatory = $true)][string]$Constat,
        [Parameter(Mandatory = $true)][string]$Recommandation
    )

    $couleur = switch ($Statut) {
        'CONFORME'     { 'Green' }
        'NON CONFORME' { 'Red' }
        default        { 'Yellow' }
    }

    Write-Host ("  [{0,-12}] {1,-42} {2}" -f $Statut, $Controle, $Constat) -ForegroundColor $couleur

    $rapport.Add([pscustomobject]@{
        Categorie      = $Categorie
        Controle       = $Controle
        Statut         = $Statut
        Constat        = $Constat
        Recommandation = $Recommandation
        Date           = (Get-Date)
    })
}

function Write-Section {
    param([string]$Titre)
    Write-Host ""
    Write-Host ("==> $Titre") -ForegroundColor Cyan
}

function Get-ValeurRegistre {
    <# Lecture défensive du registre : renvoie un objet indiquant si la valeur
       existe, ce qui évite d'interpréter une absence comme un réglage sûr. #>
    param(
        [Parameter(Mandatory = $true)][string]$Chemin,
        [Parameter(Mandatory = $true)][string]$Nom
    )

    try {
        if (-not (Test-Path -Path $Chemin)) {
            return [pscustomobject]@{ Existe = $false; Valeur = $null }
        }
        $propriete = Get-ItemProperty -Path $Chemin -Name $Nom -ErrorAction Stop
        return [pscustomobject]@{ Existe = $true; Valeur = $propriete.$Nom }
    }
    catch {
        return [pscustomobject]@{ Existe = $false; Valeur = $null }
    }
}

# --- Contexte ----------------------------------------------------------------

try {
    $domaine = Get-ADDomain @parametresAD
    $foret = Get-ADForest @parametresAD
}
catch {
    Write-Host "[ERREUR] Domaine injoignable : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

Write-Host ""
Write-Host ("Audit de durcissement — domaine {0} (forêt {1})" -f $domaine.DNSRoot, $foret.Name) -ForegroundColor White
Write-Host ("Base de référence : longueur ≥ {0}, historique ≥ {1}, verrouillage ≤ {2} tentatives" -f `
    $LongueurMinimale, $HistoriqueMinimum, $TentativesMax)

# SID utilisés pour résoudre les groupes à privilèges indépendamment de la langue
# de l'annuaire (les noms de groupes sont localisés, les SID ne le sont pas).
$sidDomaine = $domaine.DomainSID.Value
$sidForet = $sidDomaine
try {
    $racineForet = $foret.RootDomain
    if ($racineForet -and $racineForet -ne $domaine.DNSRoot) {
        $sidForet = (Get-ADDomain -Identity $racineForet @parametresAD).DomainSID.Value
    }
}
catch {
    Write-Verbose "SID de la racine de forêt non résolu, SID du domaine utilisé : $($_.Exception.Message)"
}

# --- 1 à 4. Stratégie de mot de passe et verrouillage ------------------------

Write-Section "Stratégie de mot de passe et verrouillage du domaine"

$strategie = $null
try {
    $strategie = Get-ADDefaultDomainPasswordPolicy @parametresAD
}
catch {
    Write-Verbose "Stratégie par défaut illisible : $($_.Exception.Message)"
}

if (-not $strategie) {
    Add-Controle -Categorie 'Mots de passe' -Controle 'Stratégie du domaine' -Statut 'À VÉRIFIER' `
        -Constat 'stratégie par défaut illisible' `
        -Recommandation 'Relancer avec un compte disposant au minimum des droits de lecteur sur le domaine.'
}
else {
    # 1. Longueur minimale
    if ($strategie.MinPasswordLength -ge $LongueurMinimale) {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Longueur minimale du mot de passe' -Statut 'CONFORME' `
            -Constat ("{0} caractères" -f $strategie.MinPasswordLength) `
            -Recommandation ("Maintenir au moins {0} caractères." -f $LongueurMinimale)
    }
    else {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Longueur minimale du mot de passe' -Statut 'NON CONFORME' `
            -Constat ("{0} caractères seulement" -f $strategie.MinPasswordLength) `
            -Recommandation ("Porter à {0} caractères minimum (ANSSI : 12 minimum, 14 recommandé) via une GPO de stratégie de mot de passe." -f $LongueurMinimale)
    }

    # 2. Historique
    if ($strategie.PasswordHistoryCount -ge $HistoriqueMinimum) {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Historique des mots de passe' -Statut 'CONFORME' `
            -Constat ("{0} mots de passe mémorisés" -f $strategie.PasswordHistoryCount) `
            -Recommandation ("Conserver au moins {0} mots de passe." -f $HistoriqueMinimum)
    }
    else {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Historique des mots de passe' -Statut 'NON CONFORME' `
            -Constat ("{0} mots de passe mémorisés" -f $strategie.PasswordHistoryCount) `
            -Recommandation ("Porter l'historique à {0} : un historique trop court favorise le recyclage immédiat du mot de passe précédent." -f $HistoriqueMinimum)
    }

    # 3. Expiration
    $joursExpiration = if ($strategie.MaxPasswordAge) { [int]$strategie.MaxPasswordAge.TotalDays } else { 0 }
    if ($joursExpiration -le 0) {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Expiration des mots de passe' -Statut 'NON CONFORME' `
            -Constat 'aucune expiration (MaxPasswordAge = 0)' `
            -Recommandation 'Définir une durée de vie (90 à 365 jours selon la politique), sauf pour les rares comptes techniques justifiés par une exception documentée.'
    }
    elseif ($joursExpiration -gt 365) {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Expiration des mots de passe' -Statut 'À VÉRIFIER' `
            -Constat ("{0} jours" -f $joursExpiration) `
            -Recommandation 'Durée supérieure à un an : à justifier par une exception de sécurité documentée.'
    }
    else {
        Add-Controle -Categorie 'Mots de passe' -Controle 'Expiration des mots de passe' -Statut 'CONFORME' `
            -Constat ("{0} jours" -f $joursExpiration) `
            -Recommandation 'Conserver une durée de vie inférieure ou égale à 365 jours.'
    }

    # 4. Verrouillage de compte
    if ($strategie.LockoutThreshold -eq 0) {
        Add-Controle -Categorie 'Verrouillage' -Controle 'Verrouillage de compte' -Statut 'NON CONFORME' `
            -Constat 'AUCUN verrouillage (LockoutThreshold = 0)' `
            -Recommandation 'Activer le verrouillage : 5 à 10 tentatives, durée 15 minutes minimum. Sans verrouillage, une attaque par dictionnaire est illimitée.'
    }
    elseif ($strategie.LockoutThreshold -gt $TentativesMax) {
        Add-Controle -Categorie 'Verrouillage' -Controle 'Seuil de verrouillage' -Statut 'NON CONFORME' `
            -Constat ("{0} tentatives (maximum toléré : {1})" -f $strategie.LockoutThreshold, $TentativesMax) `
            -Recommandation ("Abaisser le seuil à {0} tentatives maximum, avec un déverrouillage automatique après 15 minutes." -f $TentativesMax)
    }
    else {
        $dureeVerrou = if ($strategie.LockoutDuration) { [int]$strategie.LockoutDuration.TotalMinutes } else { 0 }
        $statut = if ($dureeVerrou -ge 15) { 'CONFORME' } else { 'À VÉRIFIER' }
        Add-Controle -Categorie 'Verrouillage' -Controle 'Seuil et durée de verrouillage' -Statut $statut `
            -Constat ("{0} tentatives, verrouillage de {1} minute(s), fenêtre {2} minute(s)" -f `
                $strategie.LockoutThreshold, $dureeVerrou, [int]$strategie.LockoutObservationWindow.TotalMinutes) `
            -Recommandation 'Conserver un verrouillage d''au moins 15 minutes pour ralentir les attaques par force brute.'
    }
}

# --- 5. Comptes à privilèges élevés -----------------------------------------

Write-Section "Comptes à privilèges élevés"

try {
    $privilegies = @(Get-ADUser -Filter 'AdminCount -eq 1' -Properties AdminCount,
            PasswordNeverExpires, MemberOf, LastLogonDate, DistinguishedName @parametresAD)

    $privilegiesActifs = @($privilegies | Where-Object { $_.Enabled })
    $privilegiesSansExpiration = @($privilegiesActifs | Where-Object { $_.PasswordNeverExpires })

    if ($privilegiesActifs.Count -eq 0) {
        Add-Controle -Categorie 'Privilèges' -Controle 'Comptes à privilèges élevés (AdminCount = 1)' -Statut 'À VÉRIFIER' `
            -Constat 'aucun compte marqué AdminCount = 1' `
            -Recommandation 'Vérifier que les groupes à privilèges contiennent bien les comptes attendus (l''attribut AdminCount est posé automatiquement par l''annuaire).'
    }
    else {
        Write-Verbose ("Comptes à privilèges : {0}" -f (($privilegiesActifs | ForEach-Object { $_.SamAccountName }) -join ', '))
        Add-Controle -Categorie 'Privilèges' -Controle 'Comptes à privilèges élevés (AdminCount = 1)' -Statut 'CONFORME' `
            -Constat ("{0} compte(s) activé(s) — {1}" -f $privilegiesActifs.Count, (($privilegiesActifs | Select-Object -First 8 | ForEach-Object { $_.SamAccountName }) -join ', ')) `
            -Recommandation 'Revue nominative trimestrielle : tout compte à privilèges doit être nominatif, distinct du compte courant et journalisé.'
    }

    if ($privilegiesSansExpiration.Count -eq 0) {
        Add-Controle -Categorie 'Privilèges' -Controle 'Mots de passe non expirants parmi les comptes à privilèges' -Statut 'CONFORME' `
            -Constat 'aucun compte à privilèges avec mot de passe non expirant' `
            -Recommandation 'Maintenir cette situation : un mot de passe d''administration éternel est une porte dérobée permanente.'
    }
    else {
        Add-Controle -Categorie 'Privilèges' -Controle 'Mots de passe non expirants parmi les comptes à privilèges' -Statut 'NON CONFORME' `
            -Constat ("{0} compte(s) : {1}" -f $privilegiesSansExpiration.Count, (($privilegiesSansExpiration | Select-Object -First 8 | ForEach-Object { $_.SamAccountName }) -join ', ')) `
            -Recommandation 'Retirer l''option « le mot de passe n''expire jamais » et documenter les rares exceptions (compte de service à mot de passe géré).'
    }
}
catch {
    Add-Controle -Categorie 'Privilèges' -Controle 'Comptes à privilèges élevés (AdminCount = 1)' -Statut 'À VÉRIFIER' `
        -Constat "lecture impossible : $($_.Exception.Message)" `
        -Recommandation 'Relancer l''audit avec un compte disposant des droits de lecture sur l''ensemble du domaine.'
}

# --- 6. Groupes à privilèges -------------------------------------------------

$groupesPrivileges = @(
    @{ Nom = 'Domain Admins';     Sid = "$sidDomaine-512"; Attendu = 'nominatif, limité' }
    @{ Nom = 'Enterprise Admins'; Sid = "$sidForet-519";   Attendu = 'vide hors opération sur la forêt' }
    @{ Nom = 'Schema Admins';     Sid = "$sidForet-518";   Attendu = 'vide hors modification de schéma' }
)

foreach ($definition in $groupesPrivileges) {

    try {
        $groupe = Get-ADGroup -Identity $definition.Sid -Properties Members -ErrorAction Stop @parametresAD
        $membres = @($groupe.Members | ForEach-Object {
            try { Get-ADObject -Identity $_ -Properties sAMAccountName -ErrorAction Stop @parametresAD }
            catch { $null }
        } | Where-Object { $_ })

        $liste = ($membres | ForEach-Object { $_.sAMAccountName }) -join ', '

        if ($membres.Count -eq 0) {
            Add-Controle -Categorie 'Groupes à privilèges' -Controle ("Membres de {0}" -f $definition.Nom) -Statut 'CONFORME' `
                -Constat 'groupe vide' `
                -Recommandation ("Conserver le groupe vide : {0}." -f $definition.Attendu)
        }
        elseif ($definition.Nom -ne 'Domain Admins') {
            Add-Controle -Categorie 'Groupes à privilèges' -Controle ("Membres de {0}" -f $definition.Nom) -Statut 'À VÉRIFIER' `
                -Constat ("{0} membre(s) : {1}" -f $membres.Count, $liste) `
                -Recommandation ("Ces groupes servent aux opérations sur la forêt et devraient rester vides : {0}. Vérifier que la présence est temporaire et justifiée." -f $definition.Attendu)
        }
        else {
            Add-Controle -Categorie 'Groupes à privilèges' -Controle ("Membres de {0}" -f $definition.Nom) -Statut 'CONFORME' `
                -Constat ("{0} membre(s) : {1}" -f $membres.Count, $liste) `
                -Recommandation 'Privilège à attribuer au cas par cas, jamais à un groupe large ni à un compte de service.'
        }
    }
    catch {
        Add-Controle -Categorie 'Groupes à privilèges' -Controle ("Membres de {0}" -f $definition.Nom) -Statut 'À VÉRIFIER' `
            -Constat "lecture impossible : $($_.Exception.Message)" `
            -Recommandation 'Vérifier manuellement la composition du groupe dans la console ADUC ou GPMC.'
    }
}

# --- 7. Délégation Kerberos non contrainte ----------------------------------

Write-Section "Délégation Kerberos"

try {
    # Bit 524288 (TRUSTED_FOR_DELEGATION) dans userAccountControl : couvre les
    # comptes utilisateurs ET ordinateurs.
    $delegations = @(Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
        -Properties sAMAccountName, primaryGroupID, objectClass @parametresAD)

    # Les contrôleurs de domaine portent légitimement ce bit (primaryGroupID 516)
    $delegationsSuspectes = @($delegations | Where-Object { $_.primaryGroupID -ne 516 })

    if ($delegationsSuspectes.Count -eq 0) {
        Add-Controle -Categorie 'Kerberos' -Controle 'Délégation non contrainte' -Statut 'CONFORME' `
            -Constat 'aucun compte hors contrôleur de domaine (bit TRUSTED_FOR_DELEGATION)' `
            -Recommandation 'Réserver la délégation non contrainte aux contrôleurs ; utiliser la délégation contrainte si un service en a besoin.'
    }
    else {
        Add-Controle -Categorie 'Kerberos' -Controle 'Délégation non contrainte' -Statut 'NON CONFORME' `
            -Constat ("{0} compte(s) : {1}" -f $delegationsSuspectes.Count, (($delegationsSuspectes | Select-Object -First 8 | ForEach-Object { $_.sAMAccountName }) -join ', ')) `
            -Recommandation 'Retirer « Faire confiance à cet ordinateur/utilisateur pour la délégation » : une délégation non contrainte permet à un attaquant de capturer des tickets Kerberos d''administration.'
    }
}
catch {
    Add-Controle -Categorie 'Kerberos' -Controle 'Délégation non contrainte' -Statut 'À VÉRIFIER' `
        -Constat "lecture impossible : $($_.Exception.Message)" `
        -Recommandation 'Contrôler manuellement l''onglet Délégation des comptes d''ordinateurs et de service.'
}

# --- 8. Durée de vie des tickets Kerberos -----------------------------------

try {
    $rootDSE = Get-ADRootDSE @parametresAD
    $dnServiceAnnuaire = "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)"
    $serviceAnnuaire = Get-ADObject -Identity $dnServiceAnnuaire `
        -Properties maxTicketAge, maxRenewAge @parametresAD

    $dureeTicket = if ($serviceAnnuaire.maxTicketAge) { [int]$serviceAnnuaire.maxTicketAge } else { 10 }
    $dureeRenouv = if ($serviceAnnuaire.maxRenewAge) { [int]$serviceAnnuaire.maxRenewAge } else { 7 }

    if ($dureeTicket -le 10 -and $dureeRenouv -le 7) {
        Add-Controle -Categorie 'Kerberos' -Controle 'Durée de vie des tickets Kerberos' -Statut 'CONFORME' `
            -Constat ("ticket {0} h, renouvellement {1} jour(s)" -f $dureeTicket, $dureeRenouv) `
            -Recommandation 'Conserver les valeurs par défaut ou les réduire : Microsoft recommande 10 heures maximum.'
    }
    else {
        Add-Controle -Categorie 'Kerberos' -Controle 'Durée de vie des tickets Kerberos' -Statut 'NON CONFORME' `
            -Constat ("ticket {0} h, renouvellement {1} jour(s)" -f $dureeTicket, $dureeRenouv) `
            -Recommandation 'Réduire maxTicketAge à 10 heures et maxRenewAge à 7 jours : une durée allongée prolonge la validité d''un ticket volé.'
    }
}
catch {
    Add-Controle -Categorie 'Kerberos' -Controle 'Durée de vie des tickets Kerberos' -Statut 'À VÉRIFIER' `
        -Constat "lecture impossible : $($_.Exception.Message)" `
        -Recommandation 'Contrôler la stratégie « Durée de vie maximale du ticket Kerberos » dans la GPO Default Domain Policy.'
}

# --- 9. Source de temps (NTP) ------------------------------------------------

Write-Section "Horodatage, SMB et LDAP"

$sourceNtp = $null
try {
    $resultatNtp = (& w32tm.exe /query /source 2>&1 | Out-String).Trim()
    if ($resultatNtp -and $resultatNtp -notmatch '^(The command completed|Erreur|Error)') {
        $sourceNtp = ($resultatNtp -split "`r?`n")[0].Trim()
    }
}
catch {
    Write-Verbose "w32tm indisponible : $($_.Exception.Message)"
}

if (-not $sourceNtp) {
    Add-Controle -Categorie 'Horodatage' -Controle 'Source de temps (NTP)' -Statut 'À VÉRIFIER' `
        -Constat 'source de temps illisible (service w32time ou droits insuffisants)' `
        -Recommandation 'Exécuter w32tm /query /source en administrateur sur le contrôleur : le serveur PDCe doit pointer vers une source NTP fiable.'
}
elseif ($sourceNtp -match 'Local CMOS|Free-running|Horloge locale|non synchronis') {
    Add-Controle -Categorie 'Horodatage' -Controle 'Source de temps (NTP)' -Statut 'NON CONFORME' `
        -Constat $sourceNtp `
        -Recommandation 'Configurer une source NTP externe sur le PDCe (w32tm /config /manualpeerlist:... /syncfromflags:manual /update) : un décalage supérieur à 5 minutes casse l''authentification Kerberos.'
}
else {
    Add-Controle -Categorie 'Horodatage' -Controle 'Source de temps (NTP)' -Statut 'CONFORME' `
        -Constat $sourceNtp `
        -Recommandation 'Vérifier la supervision du décalage horaire (w32tm /stripchart) et l''ouverture UDP 123 en sortie.'
}

# --- 10. SMBv1 ---------------------------------------------------------------

$smb1Serveur = Get-ValeurRegistre -Chemin 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Nom 'SMB1'
$smb1Client = Get-ValeurRegistre -Chemin 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Nom 'Start'

$smb1Actif = ($smb1Serveur.Existe -and $smb1Serveur.Valeur -ne 0) -or
             ($smb1Client.Existe -and $smb1Client.Valeur -ne 4)

if (-not $smb1Serveur.Existe -and -not $smb1Client.Existe) {
    Add-Controle -Categorie 'SMB' -Controle 'SMBv1 désactivé' -Statut 'À VÉRIFIER' `
        -Constat 'clés de registre SMB1 absentes de cette machine' `
        -Recommandation 'Exécuter ce contrôle sur le contrôleur de domaine, en administrateur : Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.'
}
elseif ($smb1Actif) {
    Add-Controle -Categorie 'SMB' -Controle 'SMBv1 désactivé' -Statut 'NON CONFORME' `
        -Constat ("SMB1 serveur = {0} / pilote mrxsmb10 = {1}" -f `
            $(if ($smb1Serveur.Existe) { $smb1Serveur.Valeur } else { 'absent' }),
            $(if ($smb1Client.Existe) { $smb1Client.Valeur } else { 'absent' })) `
        -Recommandation 'Désactiver SMBv1 (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart) : le protocole est exploitable par EternalBlue/WannaCry.'
}
else {
    Add-Controle -Categorie 'SMB' -Controle 'SMBv1 désactivé' -Statut 'CONFORME' `
        -Constat 'SMB1 = 0 et pilote mrxsmb10 = 4 (désactivé)' `
        -Recommandation 'Vérifier qu''aucun équipement ancien (imprimante, NAS) ne dépend encore de SMBv1 avant de supprimer la fonctionnalité.'
}

# --- 11. Signature LDAP et liaison de canal ---------------------------------

$ldapSigning = Get-ValeurRegistre -Chemin 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Nom 'LDAPServerIntegrity'
$ldapChannel = Get-ValeurRegistre -Chemin 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Nom 'LdapEnforceChannelBinding'

if (-not $ldapSigning.Existe) {
    Add-Controle -Categorie 'LDAP' -Controle 'Signature LDAP requise (LDAPServerIntegrity)' -Statut 'NON CONFORME' `
        -Constat 'valeur absente (signature non exigée)' `
        -Recommandation 'Définir LDAPServerIntegrity = 2 (signature requise) via GPO (Contrôleur de domaine : signature du serveur LDAP), après avoir vérifié que les clients le supportent.'
}
elseif ($ldapSigning.Valeur -eq 2) {
    Add-Controle -Categorie 'LDAP' -Controle 'Signature LDAP requise (LDAPServerIntegrity)' -Statut 'CONFORME' `
        -Constat 'LDAPServerIntegrity = 2 (signature requise)' `
        -Recommandation 'Conserver la signature requise : elle bloque les attaques par relais NTLM/DCSync non signées.'
}
else {
    Add-Controle -Categorie 'LDAP' -Controle 'Signature LDAP requise (LDAPServerIntegrity)' -Statut 'NON CONFORME' `
        -Constat ("LDAPServerIntegrity = {0} (négociation, pas d'exigence)" -f $ldapSigning.Valeur) `
        -Recommandation 'Passer en mode « Exiger la signature » (valeur 2) : le mode négocié accepte encore les liaisons non signées.'
}

if (-not $ldapChannel.Existe) {
    Add-Controle -Categorie 'LDAP' -Controle 'Liaison de canal LDAP (LdapEnforceChannelBinding)' -Statut 'À VÉRIFIER' `
        -Constat 'valeur absente (protection par défaut du système)' `
        -Recommandation 'Positionner LdapEnforceChannelBinding = 2 (toujours) après validation des clients : protège contre le relais d''authentification vers LDAP.'
}
elseif ($ldapChannel.Valeur -eq 2) {
    Add-Controle -Categorie 'LDAP' -Controle 'Liaison de canal LDAP (LdapEnforceChannelBinding)' -Statut 'CONFORME' `
        -Constat 'LdapEnforceChannelBinding = 2 (toujours)' `
        -Recommandation 'Conserver la liaison de canal obligatoire.'
}
else {
    Add-Controle -Categorie 'LDAP' -Controle 'Liaison de canal LDAP (LdapEnforceChannelBinding)' -Statut 'À VÉRIFIER' `
        -Constat ("LdapEnforceChannelBinding = {0}" -f $ldapChannel.Valeur) `
        -Recommandation 'Passer à la valeur 2 (toujours exiger) pour empêcher le relais d''authentification.'
}

# --- Bilan -------------------------------------------------------------------

$nbNonConforme = @($rapport | Where-Object Statut -eq 'NON CONFORME').Count
$nbAVerifier = @($rapport | Where-Object Statut -eq 'À VÉRIFIER').Count
$nbConforme = @($rapport | Where-Object Statut -eq 'CONFORME').Count

Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  Contrôles effectués : {0}" -f $rapport.Count)
Write-Host ("  CONFORME            : {0}" -f $nbConforme) -ForegroundColor $(if ($nbConforme) { 'Green' } else { 'Gray' })
Write-Host ("  À VÉRIFIER          : {0}" -f $nbAVerifier) -ForegroundColor $(if ($nbAVerifier) { 'Yellow' } else { 'Gray' })
Write-Host ("  NON CONFORME        : {0}" -f $nbNonConforme) -ForegroundColor $(if ($nbNonConforme) { 'Red' } else { 'Gray' })
Write-Host ""
Write-Host "Rappel : ce contrôle est en lecture seule, aucune modification n'a été appliquée." -ForegroundColor DarkGray

if ($ExporterCsv) {
    $rapport | Export-Csv -Path $ExporterCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
    Write-Host ("Rapport exporté vers {0}" -f $ExporterCsv) -ForegroundColor Cyan
}

# Sortie exploitable dans un pipeline
if ($ProblemesSeulement) {
    $rapport | Where-Object { $_.Statut -in @('NON CONFORME', 'À VÉRIFIER') }
}
else {
    $rapport
}

if ($nbNonConforme -gt 0) { exit 2 }
if ($nbAVerifier -gt 0) { exit 1 }
exit 0
