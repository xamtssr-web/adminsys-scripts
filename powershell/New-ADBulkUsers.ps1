<#
.SYNOPSIS
    Crée des comptes Active Directory en masse depuis un fichier CSV.

.DESCRIPTION
    Lit un CSV (Nom, Prenom, Service, Fonction, Login, Groupes…), crée les
    comptes dans l'OU cible, les ajoute à leurs groupes et génère un mot de
    passe aléatoire conforme à la stratégie de complexité du domaine.

    Le mot de passe n'est jamais affiché en clair : un fichier de résultats
    options (chemin -CheminResultats) le stocke, à remettre aux utilisateurs
    par un canal sûr puis à détruire.

    Le paramètre -WhatIf permet de simuler l'intégralité du traitement sans
    rien créer dans l'annuaire — indispensable avant un import de masse.

.PARAMETER CheminCsv
    Fichier CSV source. Colonnes attendues : Nom, Prenom, Service, Fonction.
    Colonnes optionnelles : Login (sinon dérivé du prénom et du nom), Groupes
    (séparés par des points-virgules), OU (sinon -OUCible).

.PARAMETER OUCible
    OU de destination par défaut, au format DN.
    Exemple : 'OU=Utilisateurs,OU=MonEntreprise,DC=exemple,DC=lab'

.PARAMETER Domaine
    Suffixe DNS du domaine pour l'UPN et l'adresse mail. Déduit du domaine
    courant si non fourni.

.PARAMETER LongueurMotDePasse
    Longueur des mots de passe générés (défaut : 16).

.PARAMETER CheminResultats
    Fichier CSV de sortie contenant logins et mots de passe générés.
    À protéger en écriture et à détruire après communication.

.PARAMETER SeparateurCsv
    Séparateur du fichier CSV source (défaut : point-virgule, usage français
    courant dans Excel).

.EXAMPLE
    .\New-ADBulkUsers.ps1 -CheminCsv .\utilisateurs.csv `
        -OUCible 'OU=Utilisateurs,DC=exemple,DC=lab' -WhatIf

    Simulation : affiche tout ce qui serait créé, sans rien modifier.

.EXAMPLE
    .\New-ADBulkUsers.ps1 -CheminCsv .\stagiaires.csv `
        -OUCible 'OU=Stagiaires,DC=exemple,DC=lab' `
        -CheminResultats .\resultats.csv

    Création réelle avec export des identifiants.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT), droits de création de comptes
    Version     : 1.0
    Codes retour: 0 = succès complet, 1 = au moins un échec
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Chemin du fichier CSV source")]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CheminCsv,

    [Parameter(Mandatory = $true, HelpMessage = "OU de destination au format DN")]
    [string]$OUCible,

    [Parameter(Mandatory = $false)]
    [string]$Domaine,

    [Parameter(Mandatory = $false)]
    [ValidateRange(12, 64)]
    [int]$LongueurMotDePasse = 16,

    [Parameter(Mandatory = $false)]
    [string]$CheminResultats,

    [Parameter(Mandatory = $false)]
    [ValidateLength(1, 1)]
    [string]$SeparateurCsv = ';'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Fonctions internes ------------------------------------------------------

function New-MotDePasseComplexe {
    <# Génère un mot de passe respectant la complexité Windows courante :
       majuscules, minuscules, chiffres et caractères spéciaux.
       Les caractères ambigus (O/0, l/1, I) sont volontairement exclus :
       ils provoquent des échecs de saisie au premier login. #>
    param([int]$Longueur = 16)

    $minuscules = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray()
    $majuscules = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $chiffres   = '23456789'.ToCharArray()
    $speciaux   = '!@#$%^&*-_+=?'.ToCharArray()
    $tout       = $minuscules + $majuscules + $chiffres + $speciaux

    # Garantit au moins un caractère de chaque catégorie
    $motDePasse = @(
        $minuscules | Get-Random
        $majuscules | Get-Random
        $chiffres   | Get-Random
        $speciaux   | Get-Random
    )

    while ($motDePasse.Count -lt $Longueur) {
        $motDePasse += $tout | Get-Random
    }

    # Mélange pour éviter une position fixe des catégories
    return -join ($motDePasse | Sort-Object { Get-Random })
}

function Remove-Diacritiques {
    <# Supprime les accents : un identifiant de connexion doit rester
       en ASCII pour éviter les surprises entre systèmes. #>
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

function New-Login {
    <# Construit un identifiant unique au format prenom.nom, tronqué à 20
       caractères (limite sAMAccountName) et suffixé en cas de collision. #>
    param(
        [string]$Prenom,
        [string]$Nom
    )

    $base = ("{0}.{1}" -f (Remove-Diacritiques $Prenom), (Remove-Diacritiques $Nom)).ToLower()
    $base = $base -replace '[^a-z0-9.]', ''
    if ($base.Length -gt 20) { $base = $base.Substring(0, 20) }

    $candidat = $base
    $suffixe = 1
    while (Get-ADUser -Filter "sAMAccountName -eq '$candidat'" -ErrorAction SilentlyContinue) {
        $suffixe++
        $tronque = if ($base.Length -gt 17) { $base.Substring(0, 17) } else { $base }
        $candidat = "{0}{1}" -f $tronque, $suffixe
    }
    return $candidat
}

# --- Vérifications préalables -----------------------------------------------
Write-Verbose "Chargement du module ActiveDirectory"
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Get-ADDomain -ErrorAction SilentlyContinue)) {
    throw "Impossible de contacter un contrôleur de domaine. Vérifiez votre appartenance au domaine."
}

if (-not $Domaine) {
    $Domaine = (Get-ADDomain).DNSRoot
    Write-Verbose "Domaine déduit : $Domaine"
}

if (-not (Get-ADOrganizationalUnit -Identity $OUCible -ErrorAction SilentlyContinue)) {
    throw "OU introuvable : $OUCible"
}

$donnees = Import-Csv -Path $CheminCsv -Delimiter $SeparateurCsv -Encoding UTF8
if (-not $donnees) { throw "Le fichier CSV ne contient aucune ligne : $CheminCsv" }

$colonnesRequises = @('Nom', 'Prenom')
$colonnesPresentes = $donnees[0].PSObject.Properties.Name
foreach ($colonne in $colonnesRequises) {
    if ($colonne -notin $colonnesPresentes) {
        throw "Colonne obligatoire absente du CSV : $colonne (présentes : $($colonnesPresentes -join ', '))"
    }
}

Write-Host ("Import de {0} compte(s) depuis {1}" -f $donnees.Count, (Split-Path $CheminCsv -Leaf))
Write-Host ("OU de destination : {0}" -f $OUCible)
Write-Host ("Domaine           : {0}" -f $Domaine)

# --- Traitement --------------------------------------------------------------
$resultats = [System.Collections.Generic.List[object]]::new()
$nbCrees = 0
$nbIgnores = 0
$nbEchecs = 0

foreach ($ligne in $donnees) {

    $nom = (Remove-Diacritiques $ligne.Nom).ToString().Trim()
    $prenom = (Remove-Diacritiques $ligne.Prenom).ToString().Trim()

    if ([string]::IsNullOrWhiteSpace($nom) -or [string]::IsNullOrWhiteSpace($prenom)) {
        Write-Warning "Ligne ignorée (nom ou prénom vide) : $($ligne | ConvertTo-Json -Compress)"
        $nbIgnores++
        continue
    }

    $login = if ($ligne.Login) { $ligne.Login } else { New-Login -Prenom $prenom -Nom $nom }
    $ouCompte = if ($ligne.OU) { $ligne.OU } else { $OUCible }
    $motDePasse = New-MotDePasseComplexe -Longueur $LongueurMotDePasse
    $motDePasseSecurise = ConvertTo-SecureString $motDePasse -AsPlainText -Force

    $nomComplet = "$prenom $nom"

    # -WhatIf est propagé : rien n'est créé en mode simulation
    if (-not $PSCmdlet.ShouldProcess($login, "Création du compte « $nomComplet » dans $ouCompte")) {
        $nbCrees++
        continue
    }

    try {
        $parametres = @{
            Name                  = $nomComplet
            GivenName             = $prenom
            Surname               = $nom
            SamAccountName        = $login
            UserPrincipalName     = "$login@$Domaine"
            DisplayName           = $nomComplet
            Path                  = $ouCompte
            AccountPassword       = $motDePasseSecurise
            Enabled               = $true
            ChangePasswordAtLogon = $true
        }
        if ($ligne.Service)  { $parametres['Department'] = $ligne.Service }
        if ($ligne.Fonction) { $parametres['Title'] = $ligne.Fonction }

        New-ADUser @parametres

        if ($ligne.Groupes) {
            foreach ($groupe in ($ligne.Groupes -split ';' | Where-Object { $_ })) {
                $groupe = $groupe.Trim()
                try {
                    Add-ADGroupMember -Identity $groupe -Members $login -ErrorAction Stop
                    Write-Verbose "  $login ajouté au groupe $groupe"
                }
                catch {
                    Write-Warning "Groupe « $groupe » : $($_.Exception.Message)"
                }
            }
        }

        $resultats.Add([pscustomobject]@{
            Login      = $login
            NomComplet = $nomComplet
            OU         = $ouCompte
            MotDePasse = $motDePasse
        })
        $nbCrees++
        Write-Host ("  [OK]    {0} ({1})" -f $login, $nomComplet)
    }
    catch {
        $nbEchecs++
        Write-Warning ("  [ECHEC] {0} : {1}" -f $login, $_.Exception.Message)
    }
}

# --- Export des identifiants -------------------------------------------------
if ($CheminResultats -and $resultats.Count -gt 0) {
    $resultats | Export-Csv -Path $CheminResultats -NoTypeInformation -Delimiter ';' -Encoding UTF8
    Write-Host ""
    Write-Host ("Identifiants exportés vers {0}" -f $CheminResultats) -ForegroundColor Yellow
    Write-Warning "Ce fichier contient des mots de passe en clair : communiquez-les par un canal sûr puis supprimez-le."
}

# --- Bilan -------------------------------------------------------------------
Write-Host ""
Write-Host "================ BILAN ================"
Write-Host ("Comptes traités    : {0}" -f $nbCrees)
Write-Host ("Lignes ignorées    : {0}" -f $nbIgnores)
Write-Host ("Échecs             : {0}" -f $nbEchecs)

if ($nbEchecs -gt 0) { exit 1 }
exit 0
