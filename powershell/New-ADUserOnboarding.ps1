<#
.SYNOPSIS
    Prépare l'arrivée complète d'un nouvel utilisateur Active Directory.

.DESCRIPTION
    Regroupe en une seule commande tout ce qu'un administrateur fait à la main
    pour un nouvel arrivant :

      1. création du compte utilisateur (login prenom.nom unique, UPN, service,
         fonction, adresse mail) avec mot de passe temporaire conforme à la
         complexité du domaine et changement obligatoire à la première connexion ;
      2. ajout aux groupes métier correspondant au service, plus les groupes
         supplémentaires passés dans -Groupes ;
      3. création du dossier personnel, des droits NTFS (l'utilisateur concerné,
         plus SYSTEM et Domain Admins) et du partage réseau, avec rattachement du
         lecteur personnel (HomeDirectory / HomeDrive) ;
      4. blocage optionnel de l'envoi d'e-mail vers l'extérieur ;
      5. génération d'une fiche d'accueil CSV et TXT (login, mot de passe
         temporaire, groupes, lecteur réseau) à remettre à l'utilisateur.

    Le paramètre -WhatIf est fourni par [CmdletBinding()] : il simule l'intégralité
    du traitement, y compris les opérations sur les dossiers et les partages, sans
    rien créer dans l'annuaire.

    La correspondance service -> groupes métier est décrite dans $groupesParService,
    à adapter à l'organisation avant mise en production.

.PARAMETER Prenom
    Prénom de l'utilisateur (les accents sont supprimés pour construire le login).

.PARAMETER Nom
    Nom de famille de l'utilisateur (les accents sont supprimés pour le login).

.PARAMETER Service
    Service de rattachement, utilisé comme attribut Department et pour le choix des
    groupes métier (Direction, Comptabilite, Informatique, RH, Commercial,
    Technique, Logistique).

.PARAMETER Fonction
    Intitulé de poste, stocké dans l'attribut Title.

.PARAMETER OUCible
    OU de destination du compte, au format DN.
    Exemple : 'OU=Utilisateurs,DC=exemple,DC=lab'

.PARAMETER Groupes
    Groupes supplémentaires à ajouter en plus de ceux du service.

.PARAMETER CheminHome
    Emplacement du dossier personnel. Deux usages :

      - chemin UNC ('\\FICHIER01\Utilisateurs') : le partage existe déjà, le script
        crée le sous-dossier de l'utilisateur et applique les droits NTFS ;
      - chemin local ('D:\Partages\Utilisateurs') : dossier, droits NTFS et partage
        SMB sont créés par le script.

    Le sous-dossier porte le login de l'utilisateur.

.PARAMETER LettreLecteur
    Lettre du lecteur réseau personnel (défaut : H).

.PARAMETER Domaine
    Suffixe DNS du domaine pour l'UPN et l'adresse mail. Déduit du domaine courant
    si non fourni.

.PARAMETER CheminFiche
    Chemin de la fiche d'accueil sans extension : le script écrit un .csv et un .txt
    du même nom. Défaut : .\fiche-accueil-<login>-<horodatage>.
    Cette fiche contient un mot de passe en clair : la communiquer par un canal sûr
    puis la détruire.

.PARAMETER BloquerMailExterne
    Restreint l'envoi vers l'extérieur pour cette boîte. Cette restriction appartient
    à la messagerie, pas à l'annuaire : le script tente de créer une règle de
    transport si les outils de gestion Exchange sont disponibles, sinon il inscrit
    l'action dans la fiche d'accueil comme tâche à réaliser manuellement.

.PARAMETER LongueurMotDePasse
    Longueur du mot de passe temporaire généré (défaut : 16).

.EXAMPLE
    .\New-ADUserOnboarding.ps1 -Prenom 'Camille' -Nom 'Dupont' -Service 'Informatique' `
        -Fonction 'Administrateur systèmes' -OUCible 'OU=Utilisateurs,DC=exemple,DC=lab' -WhatIf

    Simulation complète : affiche compte, groupes, dossier personnel et fiche
    d'accueil prévus, sans rien créer.

.EXAMPLE
    .\New-ADUserOnboarding.ps1 -Prenom 'Camille' -Nom 'Dupont' -Service 'Informatique' `
        -Fonction 'Administrateur systèmes' -OUCible 'OU=Utilisateurs,DC=exemple,DC=lab' `
        -Groupes 'GG_VPN','GG_GLPI' -CheminHome '\\FICHIER01\Utilisateurs' -CheminFiche .\fiche-camille

    Création complète avec dossier personnel sur \\FICHIER01 et fiche d'accueil
    écrite dans fiche-camille.csv et fiche-camille.txt.

.EXAMPLE
    .\New-ADUserOnboarding.ps1 -Prenom 'Samir' -Nom 'Benali' -Service 'RH' `
        -OUCible 'OU=Utilisateurs,DC=exemple,DC=lab' -CheminHome 'D:\Partages\Utilisateurs' `
        -BloquerMailExterne

    Création avec partage local et blocage de l'envoi vers l'extérieur.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT), droits de création de comptes et de
                  gestion des partages ; outils Exchange pour le blocage d'envoi
                  externe (facultatif) ; exécution sur un hôte ayant accès au chemin
                  indiqué par -CheminHome
    Version     : 1.0
    Codes retour: 0 = compte créé et étapes complètes,
                  1 = compte créé mais au moins une étape incomplète,
                  2 = échec de la création du compte
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Prénom de l'utilisateur")]
    [string]$Prenom,

    [Parameter(Mandatory = $true, HelpMessage = "Nom de famille de l'utilisateur")]
    [string]$Nom,

    [Parameter(Mandatory = $true, HelpMessage = "Service de rattachement")]
    [string]$Service,

    [Parameter(Mandatory = $false)]
    [string]$Fonction,

    [Parameter(Mandatory = $true, HelpMessage = "OU de destination au format DN")]
    [string]$OUCible,

    [Parameter(Mandatory = $false)]
    [string[]]$Groupes,

    [Parameter(Mandatory = $false)]
    [string]$CheminHome,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Z]$')]
    [string]$LettreLecteur = 'H',

    [Parameter(Mandatory = $false)]
    [string]$Domaine,

    [Parameter(Mandatory = $false)]
    [string]$CheminFiche,

    [Parameter(Mandatory = $false)]
    [switch]$BloquerMailExterne,

    [Parameter(Mandatory = $false)]
    [ValidateRange(12, 64)]
    [int]$LongueurMotDePasse = 16
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Correspondance service -> groupes métier --------------------------------
# À ADAPTER À L'ORGANISATION : convention GG_<métier> (groupe global).
# Le groupe transverse GG_Utilisateurs porte les droits de base (partages
# communs, imprimantes, intranet).
$groupesParService = [ordered]@{
    'Direction'    = @('GG_Direction', 'GG_Utilisateurs')
    'Comptabilite' = @('GG_Comptabilite', 'GG_Utilisateurs')
    'Informatique' = @('GG_Informatique', 'GG_Utilisateurs', 'GG_Administration_Serveurs')
    'RH'           = @('GG_RH', 'GG_Utilisateurs')
    'Commercial'   = @('GG_Commercial', 'GG_Utilisateurs')
    'Technique'    = @('GG_Technique', 'GG_Utilisateurs')
    'Logistique'   = @('GG_Logistique', 'GG_Utilisateurs')
}

# --- Fonctions internes ------------------------------------------------------

function Remove-Diacritiques {
    <# Supprime les accents : un identifiant de connexion doit rester en ASCII
       pour éviter les surprises de saisie et les problèmes entre systèmes. #>
    param([string]$Chaine)

    if ([string]::IsNullOrWhiteSpace($Chaine)) { return '' }

    $normalise = $Chaine.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $normalise.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne
            [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}

function New-MotDePasseComplexe {
    <# Génère un mot de passe respectant la complexité Windows : majuscules,
       minuscules, chiffres, caractères spéciaux. Les caractères ambigus
       (O/0, l/1, I) sont exclus : ils provoquent des échecs de saisie au premier
       login, surtout au téléphone. #>
    param([int]$Longueur = 16)

    $minuscules = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray()
    $majuscules = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $chiffres = '23456789'.ToCharArray()
    $speciaux = '!@#$%^&*-_+=?'.ToCharArray()
    $tout = $minuscules + $majuscules + $chiffres + $speciaux

    $motDePasse = @(
        $minuscules | Get-Random
        $majuscules | Get-Random
        $chiffres | Get-Random
        $speciaux | Get-Random
    )

    while ($motDePasse.Count -lt $Longueur) {
        $motDePasse += $tout | Get-Random
    }

    # Mélange : évite que les catégories restent aux premières positions
    return -join ($motDePasse | Sort-Object { Get-Random })
}

function New-DossierPersonnel {
    <# Crée le dossier personnel, applique les droits NTFS (héritage coupé :
       utilisateur, SYSTEM et administrateurs du domaine uniquement) et crée le
       partage SMB si le chemin est local. #>
    param(
        [Parameter(Mandatory = $true)][string]$Chemin,
        [Parameter(Mandatory = $true)][string]$SidUtilisateur,
        [Parameter(Mandatory = $true)][string]$SidAdministrateurs,
        [Parameter(Mandatory = $true)][string]$NomPartage,
        [Parameter(Mandatory = $true)][string]$NomDomaine,
        [Parameter(Mandatory = $true)][string]$NomUtilisateur
    )

    $resultat = [ordered]@{
        Dossier = $Chemin
        DroitsNtfs = $false
        Partage = $null
        DetailErreur = $null
    }

    if (-not (Test-Path -Path $Chemin)) {
        New-Item -Path $Chemin -ItemType Directory -Force | Out-Null
    }

    try {
        $acl = Get-Acl -Path $Chemin

        # L'héritage est coupé : le dossier ne doit pas hériter de droits larges
        # posés sur le partage parent (souvent « Utilisateurs du domaine »).
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        $regles = @(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $SidUtilisateur, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                'S-1-5-18', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $SidAdministrateurs, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        )

        foreach ($regle in $regles) { $acl.AddAccessRule($regle) }
        Set-Acl -Path $Chemin -AclObject $acl
        $resultat.DroitsNtfs = $true
    }
    catch {
        $resultat.DetailErreur = "droits NTFS : $($_.Exception.Message)"
        return [pscustomobject]$resultat
    }

    # Partage SMB uniquement pour un chemin local : un partage UNC existe déjà
    if ($Chemin -notlike '\\*') {
        try {
            if (-not (Get-SmbShare -Name $NomPartage -ErrorAction SilentlyContinue)) {
                $compteUtilisateur = "$NomDomaine\$NomUtilisateur"
                New-SmbShare -Name $NomPartage -Path $Chemin -FullAccess $compteUtilisateur -ErrorAction Stop | Out-Null
                $resultat.Partage = "\\$env:COMPUTERNAME\$NomPartage"
            }
            else {
                $resultat.Partage = "\\$env:COMPUTERNAME\$NomPartage (existant)"
            }
        }
        catch {
            $resultat.DetailErreur = "partage SMB : $($_.Exception.Message)"
        }
    }
    else {
        $resultat.Partage = $Chemin
    }

    return [pscustomobject]$resultat
}

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

# --- Préparations ------------------------------------------------------------

$prenomNettoye = (Remove-Diacritiques $Prenom).ToString().Trim()
$nomNettoye = (Remove-Diacritiques $Nom).ToString().Trim()

if ([string]::IsNullOrWhiteSpace($prenomNettoye) -or [string]::IsNullOrWhiteSpace($nomNettoye)) {
    Write-Host "[ERREUR] Prénom et nom ne peuvent pas être vides." -ForegroundColor Red
    exit 2
}

try {
    $domaineAD = Get-ADDomain -ErrorAction Stop
}
catch {
    Write-Host "[ERREUR] Domaine injoignable : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

if (-not $Domaine) { $Domaine = $domaineAD.DNSRoot }

if (-not (Get-ADOrganizationalUnit -Identity $OUCible -ErrorAction SilentlyContinue)) {
    Write-Host "[ERREUR] OU introuvable : $OUCible" -ForegroundColor Red
    exit 2
}

# --- Construction du login unique -------------------------------------------

$nomComplet = "$prenomNettoye $nomNettoye"
$baseLogin = ("{0}.{1}" -f $prenomNettoye, $nomNettoye).ToLower() -replace '[^a-z0-9.]', ''
if ($baseLogin.Length -gt 20) { $baseLogin = $baseLogin.Substring(0, 20) }

$login = $baseLogin
$suffixe = 1
while (Get-ADUser -Filter "sAMAccountName -eq '$login'" -ErrorAction SilentlyContinue) {
    $suffixe++
    $tronque = if ($baseLogin.Length -gt 17) { $baseLogin.Substring(0, 17) } else { $baseLogin }
    $login = "{0}{1}" -f $tronque, $suffixe
}
if ($login -ne $baseLogin) { Write-Warning "Login $baseLogin déjà utilisé : $login retenu." }

$adresseMail = "$login@$Domaine"
$motDePasse = New-MotDePasseComplexe -Longueur $LongueurMotDePasse
$motDePasseSecurise = ConvertTo-SecureString $motDePasse -AsPlainText -Force

# Groupes métier du service + groupes supplémentaires explicites
$groupesMetier = @()
$cle = $groupesParService.Keys | Where-Object { $_ -eq $Service } | Select-Object -First 1
if ($cle) {
    $groupesMetier = @($groupesParService[$cle])
}
else {
    Write-Warning "Service « $Service » absent de la table de correspondance : seuls les groupes de -Groupes seront ajoutés."
}
$tousLesGroupes = @(@($groupesMetier) + @($Groupes) | Where-Object { $_ } | Select-Object -Unique)

# Dossier personnel
$cheminUtilisateur = $null
if ($CheminHome) { $cheminUtilisateur = Join-Path $CheminHome $login }

# Fiche d'accueil
if (-not $CheminFiche) {
    $CheminFiche = Join-Path (Get-Location) ("fiche-accueil-{0}-{1}" -f $login, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$fichierCsv = "$CheminFiche.csv"
$fichierTxt = "$CheminFiche.txt"

# --- Récapitulatif avant action ---------------------------------------------

Write-Host ""
Write-Host "Fiche d'arrivée — préparation du compte" -ForegroundColor White
Write-Host ("  Identité           : {0}" -f $nomComplet)
Write-Host ("  Login              : {0}" -f $login)
Write-Host ("  Adresse mail       : {0}" -f $adresseMail)
Write-Host ("  Service / fonction : {0} / {1}" -f $Service, $(if ($Fonction) { $Fonction } else { '(non précisé)' }))
Write-Host ("  OU de destination  : {0}" -f $OUCible)
if ($tousLesGroupes.Count -gt 0) {
    Write-Host ("  Groupes            : {0}" -f ($tousLesGroupes -join ', '))
}
if ($cheminUtilisateur) {
    Write-Host ("  Lecteur {0}:          {1}" -f $LettreLecteur, $cheminUtilisateur)
}
if ($BloquerMailExterne) {
    Write-Host "  Messagerie         : envoi vers l'extérieur à restreindre" -ForegroundColor Yellow
}

# --- Simulation ---------------------------------------------------------------

if (-not $PSCmdlet.ShouldProcess($login, "Création du compte « $nomComplet » dans $OUCible")) {
    Write-Host ""
    Write-Host "Simulation (-WhatIf) : aucune création effectuée dans l'annuaire, aucun dossier créé." -ForegroundColor Yellow
    Write-Host ("Étapes qui seraient exécutées : création de {0}, ajout à {1} groupe(s), dossier {2}, fiche {3}" -f `
        $login, $tousLesGroupes.Count, $(if ($cheminUtilisateur) { $cheminUtilisateur } else { 'non demandé' }), $fichierCsv)
    exit 0
}

# --- 1. Création du compte ---------------------------------------------------

$nbEchecs = 0
$utilisateur = $null

try {
    $parametresCreation = @{
        Name                  = $nomComplet
        GivenName             = $prenomNettoye
        Surname               = $nomNettoye
        DisplayName           = $nomComplet
        SamAccountName        = $login
        UserPrincipalName     = $adresseMail
        EmailAddress          = $adresseMail
        Path                  = $OUCible
        AccountPassword       = $motDePasseSecurise
        Enabled               = $true
        ChangePasswordAtLogon = $true
        Department            = $Service
        Description           = ("Compte créé le {0} — service {1}" -f (Get-Date -Format 'dd/MM/yyyy'), $Service)
        PassThru              = $true
    }
    if ($Fonction) { $parametresCreation['Title'] = $Fonction }
    if ($cheminUtilisateur) {
        $parametresCreation['HomeDirectory'] = $cheminUtilisateur
        $parametresCreation['HomeDrive'] = $LettreLecteur
    }

    $utilisateur = New-ADUser @parametresCreation
    Write-Host ""
    Write-Host ("  [OK]    Compte {0} créé dans {1}" -f $login, $OUCible) -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host ("[ERREUR] Création du compte {0} impossible : {1}" -f $login, $_.Exception.Message) -ForegroundColor Red
    exit 2
}

# Adresse mail dans proxyAddresses : utile en environnement sans Exchange.
# Sur un domaine géré par Exchange, c'est le service de destinataires qui fait
# autorité : ne pas forcer cet attribut dans ce cas.
try {
    Set-ADUser -Identity $utilisateur -Add @{ proxyAddresses = "SMTP:$adresseMail" }
    Write-Verbose "proxyAddresses renseigné : SMTP:$adresseMail"
}
catch {
    $nbEchecs++
    Write-Warning "  [ATTENTION] proxyAddresses non renseigné : $($_.Exception.Message)"
}

# --- 2. Groupes ---------------------------------------------------------------

$groupesAjoutes = [System.Collections.Generic.List[string]]::new()

foreach ($groupe in $tousLesGroupes) {
    try {
        Add-ADGroupMember -Identity $groupe -Members $login -ErrorAction Stop
        $groupesAjoutes.Add($groupe)
        Write-Host ("  [OK]    Ajouté au groupe {0}" -f $groupe) -ForegroundColor Green
    }
    catch {
        $nbEchecs++
        Write-Warning ("  [ECHEC] Groupe {0} : {1}" -f $groupe, $_.Exception.Message)
    }
}

# --- 3. Dossier personnel, droits NTFS et partage ----------------------------

$resumeHome = $null
if ($cheminUtilisateur) {

    $sidUtilisateur = $utilisateur.SID.Value
    $sidAdministrateurs = "$($domaineAD.DomainSID.Value)-512"
    $nomPartage = $login

    try {
        $resultatHome = New-DossierPersonnel -Chemin $cheminUtilisateur -SidUtilisateur $sidUtilisateur `
            -SidAdministrateurs $sidAdministrateurs -NomPartage $nomPartage -NomDomaine $domaineAD.NetBIOSName `
            -NomUtilisateur $login

        if ($resultatHome.DroitsNtfs) {
            Write-Host ("  [OK]    Dossier personnel {0} (droits NTFS restreints à {1})" -f `
                $cheminUtilisateur, $login) -ForegroundColor Green
        }

        if ($resultatHome.Partage) {
            Write-Host ("  [OK]    Partage {0}" -f $resultatHome.Partage) -ForegroundColor Green
        }

        if ($resultatHome.DetailErreur) {
            $nbEchecs++
            Write-Warning ("  [ATTENTION] Dossier personnel : {0}" -f $resultatHome.DetailErreur)
        }

        $resumeHome = ("{0}: {1}" -f $LettreLecteur, $resultatHome.Partage)
    }
    catch {
        $nbEchecs++
        Write-Warning ("  [ECHEC] Dossier personnel {0} : {1}" -f $cheminUtilisateur, $_.Exception.Message)
        $resumeHome = ("{0}: {1} (à créer manuellement)" -f $LettreLecteur, $cheminUtilisateur)
    }
}

# --- 4. Blocage de l'envoi vers l'extérieur ----------------------------------

$etatBlocage = 'non demandé'
if ($BloquerMailExterne) {

    # La restriction d'envoi est un paramètre de messagerie : côté Exchange, elle
    # se pose par une règle de transport (une règle globale visant un groupe est
    # préférable à une règle par utilisateur, à valider avec l'équipe messagerie).
    if (Get-Command -Name New-TransportRule -ErrorAction SilentlyContinue) {
        try {
            New-TransportRule -Name ("Blocage envoi externe - {0}" -f $login) `
                -From $adresseMail -SentToScope NotInOrganization `
                -RejectMessageReasonText "L'envoi vers l'extérieur n'est pas autorisé pour ce compte." `
                -RejectMessageEnhancedStatusCode '5.7.1' -ErrorAction Stop | Out-Null
            $etatBlocage = 'règle de transport créée'
            Write-Host ("  [OK]    Envoi externe bloqué pour {0}" -f $adresseMail) -ForegroundColor Green
        }
        catch {
            $etatBlocage = 'À FAIRE MANUELLEMENT (échec de la règle de transport)'
            $nbEchecs++
            Write-Warning ("  [ECHEC] Blocage envoi externe : {0}" -f $_.Exception.Message)
        }
    }
    else {
        $etatBlocage = 'À FAIRE MANUELLEMENT (outils Exchange absents sur cet hôte)'
        $nbEchecs++
        Write-Warning "  [ATTENTION] Blocage envoi externe : outils de gestion Exchange indisponibles."
        Write-Warning "              Créer une règle de transport pour $adresseMail depuis la console d'administration."
    }
}

# --- 5. Fiche d'accueil ------------------------------------------------------

$fiche = [pscustomobject]@{
    Date                 = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    NomComplet           = $nomComplet
    Login                = $login
    MotDePasseTemporaire = $motDePasse
    AdresseMail          = $adresseMail
    Service              = $Service
    Fonction             = $Fonction
    OU                   = $OUCible
    Groupes              = ($groupesAjoutes -join '; ')
    LecteurReseau        = $resumeHome
    BlocageEnvoiExterne  = $etatBlocage
    ChangementObligatoire = 'Oui (à la première connexion)'
}

try {
    $fiche | Export-Csv -Path $fichierCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
    ($fiche | Format-List | Out-String) | Set-Content -Path $fichierTxt -Encoding UTF8
    Write-Host ""
    Write-Host ("  [OK]    Fiche d'accueil : {0} et {1}" -f $fichierCsv, $fichierTxt) -ForegroundColor Green
}
catch {
    $nbEchecs++
    Write-Warning ("  [ECHEC] Écriture de la fiche d'accueil : {0}" -f $_.Exception.Message)
}

# --- Bilan -------------------------------------------------------------------

Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  Compte créé       : {0} ({1})" -f $login, $nomComplet)
Write-Host ("  Groupes ajoutés   : {0} sur {1} demandé(s)" -f $groupesAjoutes.Count, $tousLesGroupes.Count)
Write-Host ("  Dossier personnel : {0}" -f $(if ($resumeHome) { $resumeHome } else { 'non demandé' }))
Write-Host ("  Étape(s) en échec : {0}" -f $nbEchecs) -ForegroundColor $(if ($nbEchecs) { 'Yellow' } else { 'Gray' })
Write-Host ""
Write-Warning "La fiche d'accueil contient le mot de passe temporaire en clair : à communiquer par un canal sûr, puis à supprimer."

# Sortie exploitable dans un pipeline (le mot de passe n'est PAS inclus)
[pscustomobject]@{
    Login         = $login
    NomComplet    = $nomComplet
    AdresseMail   = $adresseMail
    OU            = $OUCible
    Groupes       = @($groupesAjoutes)
    DossierPersonnel = $cheminUtilisateur
    FicheAccueil  = $fichierCsv
    EtapesEnEchec = $nbEchecs
}

if ($nbEchecs -gt 0) { exit 1 }
exit 0
