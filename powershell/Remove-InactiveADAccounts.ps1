<#
.SYNOPSIS
    Désactive les comptes Active Directory inactifs et les place en quarantaine.

.DESCRIPTION
    Détecte les comptes utilisateurs actifs dont la dernière connexion remonte à
    plus de N jours (90 par défaut), puis applique la procédure de mise en
    quarantaine — JAMAIS de suppression :

      1. désactivation du compte (Enabled = $false) ;
      2. retrait des groupes à privilèges (résolus par SID, donc insensible à la
         langue de l'annuaire : Domain Admins, Enterprise Admins, Schema Admins,
         Administrators, Protected Users, etc.) ;
      3. déplacement du compte vers une OU de quarantaine ;
      4. annotation de la description (date de désactivation et motif) ;
      5. journalisation de chaque action dans un CSV d'audit.

    Une suppression ne se décide pas dans un script : elle suppose une période
    d'observation, une validation du responsable et une sauvegarde de l'annuaire.
    L'OU de quarantaine permet de restaurer un compte en quelques secondes en cas
    de faux positif.

    SÉCURITÉ PAR DÉFAUT : le script refuse de toucher aux comptes de service, aux
    comptes protégés (AdminCount = 1, groupe Protected Users, krbtgt, compte
    Administrateur intégré) et aux comptes ordinateurs. Sans le commutateur
    -Forcer, il fonctionne en SIMULATION (-WhatIf implicite) : rien n'est modifié
    tant que l'administrateur n'a pas relu la liste des candidats.

.PARAMETER JoursInactivite
    Seuil d'inactivité en jours (défaut : 90). Un compte dont la dernière
    connexion est antérieure à ce seuil devient candidat.

.PARAMETER OUQuarantaine
    OU de destination des comptes désactivés, au format DN.
    Exemple : 'OU=Quarantaine,DC=exemple,DC=lab'

.PARAMETER Serveur
    Contrôleur de domaine à interroger (défaut : le contrôleur en cours).

.PARAMETER JournalAudit
    Chemin du CSV d'audit. Chaque action y est ajoutée ligne par ligne en fin de
    traitement (le fichier reste exploitable même en cas d'interruption).
    Défaut : .\audit-desactivation-ad_<horodatage>.csv

.PARAMETER MotifsExclusService
    Expressions régulières identifiant les comptes techniques à ne jamais
    traiter. Par défaut : svc-, srv-, sa-, service-, adm-, app-.

.PARAMETER Forcer
    Exécute réellement les modifications. Sans ce commutateur, le script simule
    l'intégralité du traitement et affiche liste et actions prévues.

.EXAMPLE
    .\Remove-InactiveADAccounts.ps1 -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab'

    Simulation : liste les comptes inactifs depuis 90 jours et les actions prévues,
    sans rien modifier.

.EXAMPLE
    .\Remove-InactiveADAccounts.ps1 -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab' `
        -JoursInactivite 180 -JournalAudit .\audit-quarantaine.csv -Forcer

    Désactivation réelle des comptes inactifs depuis 180 jours, avec journal
    d'audit dédié.

.EXAMPLE
    .\Remove-InactiveADAccounts.ps1 -OUQuarantaine 'OU=Quarantaine,DC=exemple,DC=lab' `
        -Forcer -WhatIf

    Test complet du chemin d'exécution réel (appels ShouldProcess détaillés) sans
    aucune écriture dans l'annuaire.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : module ActiveDirectory (RSAT), droits d'écriture sur les comptes
                  cibles, OU de quarantaine préexistante, sauvegarde système
                  récente de l'annuaire (voir tombstoneLifetime).
    Version     : 1.0
    Codes retour: 0 = aucun compte candidat,
                  1 = au moins un compte traité (ou simulé),
                  2 = au moins une erreur d'exécution
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(30, 3650)]
    [int]$JoursInactivite = 90,

    [Parameter(Mandatory = $true, HelpMessage = "OU de quarantaine au format DN")]
    [string]$OUQuarantaine,

    [Parameter(Mandatory = $false)]
    [string]$Serveur,

    [Parameter(Mandatory = $false)]
    [string]$JournalAudit,

    [Parameter(Mandatory = $false)]
    [string[]]$MotifsExclusService = @('^svc[-_]', '^srv[-_]', '^sa[-_]', '^service[-_]', '^adm[-_]', '^app[-_]'),

    [Parameter(Mandatory = $false)]
    [switch]$Forcer
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --- Sécurité par défaut : simulation tant que -Forcer n'est pas fourni ------
if (-not $Forcer) {
    if (-not $PSBoundParameters.ContainsKey('WhatIf') -and -not $PSBoundParameters.ContainsKey('Confirm')) {
        $WhatIfPreference = $true
        Write-Warning "Mode SIMULATION (par défaut). Relisez la liste des candidats,"
        Write-Warning "puis relancez avec -Forcer pour appliquer les modifications."
    }
}

if (-not $JournalAudit) {
    $JournalAudit = Join-Path (Get-Location) ("audit-desactivation-ad_{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
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

$parametresAD = @{}
if ($Serveur) { $parametresAD['Server'] = $Serveur }

# --- Vérifications préalables -----------------------------------------------

try {
    $domaine = Get-ADDomain @parametresAD
}
catch {
    Write-Host "[ERREUR] Contrôleur de domaine injoignable : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

$ouCible = Get-ADOrganizationalUnit -Identity $OUQuarantaine -ErrorAction SilentlyContinue @parametresAD
if (-not $ouCible) {
    Write-Host "[ERREUR] OU de quarantaine introuvable : $OUQuarantaine" -ForegroundColor Red
    Write-Host "         Créez-la d'abord : New-ADOrganizationalUnit -Name 'Quarantaine' -Path 'DC=exemple,DC=lab'" -ForegroundColor DarkGray
    exit 2
}

# Groupes à privilèges résolus par SID : la correspondance reste correcte sur un
# annuaire anglais, allemand ou français.
try {
    $sidDomaine = (Get-ADDomain @parametresAD).DomainSID.Value
}
catch {
    Write-Host "[ERREUR] Lecture du SID de domaine impossible : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

# Le SID de la racine de forêt sert à résoudre Enterprise Admins et Schema Admins.
# Sur une forêt à domaine unique, il est identique au SID du domaine.
$sidForet = $sidDomaine
try {
    $racineForet = (Get-ADForest @parametresAD).RootDomain
    if ($racineForet -and $racineForet -ne $domaine.DNSRoot) {
        $sidForet = (Get-ADDomain -Identity $racineForet @parametresAD).DomainSID.Value
    }
}
catch {
    Write-Verbose "SID de la racine de forêt non résolu, SID du domaine utilisé : $($_.Exception.Message)"
}

$groupesSensibles = [ordered]@{
    'Domain Admins'               = "$sidDomaine-512"
    'Enterprise Admins'           = "$sidForet-519"
    'Schema Admins'               = "$sidForet-518"
    'Administrators'              = "$sidDomaine-544"
    'Account Operators'           = "$sidDomaine-548"
    'Server Operators'            = "$sidDomaine-549"
    'Print Operators'             = "$sidDomaine-550"
    'Backup Operators'            = "$sidDomaine-551"
    'Group Policy Creator Owners' = "$sidDomaine-520"
    'Key Admins'                  = "$sidDomaine-526"
    'Protected Users'             = "$sidDomaine-525"
}

$groupesResolus = [ordered]@{}
foreach ($nom in $groupesSensibles.Keys) {
    try {
        $groupe = Get-ADGroup -Identity $groupesSensibles[$nom] -ErrorAction Stop @parametresAD
        $groupesResolus[$nom] = $groupe
    }
    catch {
        Write-Verbose "Groupe à privilèges absent de cet annuaire : $nom"
    }
}

Write-Host ""
Write-Host ("Désactivation des comptes inactifs — domaine {0}" -f $domaine.DNSRoot) -ForegroundColor White
Write-Host ("Seuil d'inactivité : {0} jour(s)" -f $JoursInactivite)
Write-Host ("OU de quarantaine  : {0}" -f $OUQuarantaine)
Write-Host ("Journal d'audit    : {0}" -f $JournalAudit)
if ($WhatIfPreference) { Write-Host "Mode               : SIMULATION (-WhatIf)" -ForegroundColor Yellow }

# --- Détection des candidats -------------------------------------------------

$seuil = (Get-Date).AddDays(-$JoursInactivite)

$utilisateurs = @(Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, AdminCount,
        PasswordNeverExpires, servicePrincipalName, MemberOf, Description, DistinguishedName,
        Created, whenCreated @parametresAD)

$candidats = [System.Collections.Generic.List[object]]::new()
$exclus = [System.Collections.Generic.List[object]]::new()

foreach ($utilisateur in $utilisateurs) {

    $motif = $null

    # Un compte ordinateur n'a rien à faire ici (garde-fou si le filtre évolue)
    if ($utilisateur.ObjectClass -ne 'user') { continue }

    if (-not $utilisateur.Enabled) { continue }                       # déjà désactivé
    if ($utilisateur.SamAccountName -eq 'krbtgt') { $motif = 'compte krbtgt (protégé)' }

    # Compte Administrateur intégré du domaine (RID 500) et comptes intégrés
    if (-not $motif -and $utilisateur.SID.Value -match '-500$') { $motif = 'compte Administrateur intégré (RID 500)' }

    if (-not $motif -and $utilisateur.AdminCount -eq 1) { $motif = 'compte protégé (AdminCount = 1)' }

    if (-not $motif) {
        foreach ($nom in $groupesResolus.Keys) {
            if (@($utilisateur.MemberOf) -contains $groupesResolus[$nom].DistinguishedName) {
                $motif = "membre de $nom"
                break
            }
        }
    }

    if (-not $motif) {
        foreach ($expression in $MotifsExclusService) {
            if ($utilisateur.SamAccountName -match $expression) {
                $motif = "compte de service (motif « $expression »)"
                break
            }
        }
    }

    # Un compte porteur d'un SPN est un compte de service : il casse une
    # application métier s'il est désactivé sans concertation.
    if (-not $motif -and $utilisateur.servicePrincipalName) {
        $motif = 'compte porteur de SPN (compte de service applicatif)'
    }

    # Jamais connecté : faute de référence, on ne désactive pas à l'aveugle.
    # L'inactivité est mesurée sur la dernière connexion, à défaut sur la
    # date de création du compte.
    $derniereActivite = if ($utilisateur.LastLogonDate) { $utilisateur.LastLogonDate } else { $utilisateur.whenCreated }
    $jamaisConnecte = -not $utilisateur.LastLogonDate

    if (-not $motif) {
        if (-not $derniereActivite) {
            $motif = 'aucune date de référence (création inconnue)'
        }
        elseif ($derniereActivite -ge $seuil) {
            continue   # compte actif dans la fenêtre : hors périmètre
        }
        elseif ($jamaisConnecte) {
            $motif = 'jamais connecté depuis sa création'
        }
    }

    if ($motif) {
        $exclus.Add([pscustomobject]@{
            Login           = $utilisateur.SamAccountName
            NomComplet      = $utilisateur.Name
            MotifExclusion  = $motif
            DerniereConnexion = $utilisateur.LastLogonDate
            OU              = ($utilisateur.DistinguishedName -split ',OU=', 2)[1]
        })
        continue
    }

    $joursInactif = [int][math]::Floor(((Get-Date) - $derniereActivite).TotalDays)

    $candidats.Add([pscustomobject]@{
        Login             = $utilisateur.SamAccountName
        NomComplet        = $utilisateur.Name
        DerniereConnexion = $utilisateur.LastLogonDate
        JoursInactif      = $joursInactif
        DistinguishedName = $utilisateur.DistinguishedName
        Description       = $utilisateur.Description
        PasswordLastSet   = $utilisateur.PasswordLastSet
        PasswordNeverExpires = $utilisateur.PasswordNeverExpires
    })
}

# --- Affichage des candidats -------------------------------------------------

Write-Host ""
if ($candidats.Count -eq 0) {
    Write-Host "Aucun compte candidat à la désactivation." -ForegroundColor Green
}
else {
    Write-Host ("{0} compte(s) candidat(s) :" -f $candidats.Count) -ForegroundColor White
    Write-Host ("{0,-22} {1,-30} {2,-20} {3,10}" -f 'LOGIN', 'NOM', 'DERNIÈRE CONNEXION', 'INACTIF') -ForegroundColor White
    foreach ($candidat in ($candidats | Sort-Object JoursInactif -Descending)) {
        Write-Host ("{0,-22} {1,-30} {2,-20} {3,7} j" -f `
            $candidat.Login, $candidat.NomComplet,
            $candidat.DerniereConnexion.ToString('dd/MM/yyyy HH:mm'), $candidat.JoursInactif)
    }
}

if ($exclus.Count -gt 0) {
    Write-Host ""
    Write-Host ("{0} compte(s) exclu(s) du traitement (protection) :" -f $exclus.Count) -ForegroundColor DarkGray
    foreach ($exclusion in $exclus) {
        Write-Host ("  {0,-22} {1}" -f $exclusion.Login, $exclusion.MotifExclusion) -ForegroundColor DarkGray
    }
}

# --- Traitement --------------------------------------------------------------

$journal = [System.Collections.Generic.List[object]]::new()
$nbActions = 0
$nbErreurs = 0

function Write-Journal {
    <# Trace une action dans le CSV d'audit et la renvoie sous forme d'objet.
       Le fichier est alimenté en mode ajout : il reste exploitable même si le
       traitement est interrompu. #>
    param(
        [Parameter(Mandatory = $true)][string]$Login,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][ValidateSet('OK', 'SIMULATION', 'ECHEC', 'IGNORE')][string]$Statut,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $entree = [pscustomobject]@{
        Horodatage = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Operateur  = "$env:USERDOMAIN\$env:USERNAME"
        Login      = $Login
        Action     = $Action
        Statut     = $Statut
        Detail     = $Detail
    }

    # Compte hôte utilisé pour le journal
    $entree | Export-Csv -Path $JournalAudit -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Append
    return $entree
}

foreach ($candidat in ($candidats | Sort-Object Login)) {

    $login = $candidat.Login
    $dn = $candidat.DistinguishedName
    $horodatage = (Get-Date).ToString('yyyy-MM-dd')

    if ($PSCmdlet.ShouldProcess($login, "Désactivation et mise en quarantaine (inactif depuis $($candidat.JoursInactif) jours)")) {

        $echecCompte = $false

        # 1) Retrait des groupes à privilèges
        foreach ($nom in $groupesResolus.Keys) {
            $groupe = $groupesResolus[$nom]
            try {
                if (@((Get-ADUser -Identity $dn -Properties MemberOf @parametresAD).MemberOf) -contains $groupe.DistinguishedName) {
                    Remove-ADGroupMember -Identity $groupe.DistinguishedName -Members $dn -Confirm:$false @parametresAD
                    $journal.Add((Write-Journal -Login $login -Action "Retrait du groupe $nom" -Statut 'OK' `
                        -Detail $groupe.DistinguishedName))
                    Write-Verbose "  $login retiré de $nom"
                }
            }
            catch {
                $echecCompte = $true
                $nbErreurs++
                $journal.Add((Write-Journal -Login $login -Action "Retrait du groupe $nom" -Statut 'ECHEC' `
                    -Detail $_.Exception.Message))
                Write-Warning "  [ECHEC] $login / retrait de $nom : $($_.Exception.Message)"
            }
        }

        # 2) Désactivation + annotation de la description
        try {
            $description = if ($candidat.Description) { $candidat.Description } else { '' }
            $nouvelleDescription = ("{0} | Désactivé le {1} par script (inactif depuis {2} jours)" -f `
                $description.Trim(), $horodatage, $candidat.JoursInactif).TrimStart('| ')

            Set-ADUser -Identity $dn -Enabled $false -Description $nouvelleDescription @parametresAD
            $journal.Add((Write-Journal -Login $login -Action 'Désactivation du compte' -Statut 'OK' `
                -Detail "inactif depuis $($candidat.JoursInactif) jours (dernière connexion $($candidat.DerniereConnexion))"))
            Write-Host ("  [OK]    {0} désactivé" -f $login)
        }
        catch {
            $echecCompte = $true
            $nbErreurs++
            $journal.Add((Write-Journal -Login $login -Action 'Désactivation du compte' -Statut 'ECHEC' `
                -Detail $_.Exception.Message))
            Write-Warning "  [ECHEC] $login / désactivation : $($_.Exception.Message)"
        }

        # 3) Déplacement en quarantaine (uniquement si la désactivation a abouti)
        if (-not $echecCompte) {
            try {
                Move-ADObject -Identity $dn -TargetPath $OUQuarantaine @parametresAD
                $journal.Add((Write-Journal -Login $login -Action 'Déplacement en quarantaine' -Statut 'OK' `
                    -Detail $OUQuarantaine))
                Write-Verbose "  $login déplacé vers $OUQuarantaine"
            }
            catch {
                $nbErreurs++
                $journal.Add((Write-Journal -Login $login -Action 'Déplacement en quarantaine' -Statut 'ECHEC' `
                    -Detail $_.Exception.Message))
                Write-Warning "  [ECHEC] $login / déplacement : $($_.Exception.Message)"
            }
        }

        if (-not $echecCompte) { $nbActions++ }
    }
    else {
        # Sortie -WhatIf : on trace l'action prévue pour la revue de sécurité
        $journal.Add((Write-Journal -Login $login -Action 'Désactivation et quarantaine' -Statut 'SIMULATION' `
            -Detail "actions prévues — inactif depuis $($candidat.JoursInactif) jours"))
        $nbActions++
    }
}

# --- Bilan -------------------------------------------------------------------

$nbSimules = @($journal | Where-Object Statut -eq 'SIMULATION').Count

Write-Host ""
Write-Host "================ BILAN ================" -ForegroundColor White
Write-Host ("  Candidats détectés : {0}" -f $candidats.Count)
Write-Host ("  Comptes exclus     : {0}" -f $exclus.Count)
Write-Host ("  Comptes traités    : {0}" -f $nbActions) -ForegroundColor $(if ($nbActions) { 'Yellow' } else { 'Gray' })
if ($nbSimules) {
    Write-Host ("  Dont simulés       : {0} (aucune modification réelle)" -f $nbSimules) -ForegroundColor Yellow
}
Write-Host ("  Erreurs            : {0}" -f $nbErreurs) -ForegroundColor $(if ($nbErreurs) { 'Red' } else { 'Gray' })
Write-Host ("  Journal d'audit    : {0}" -f $JournalAudit) -ForegroundColor Cyan

if ($WhatIfPreference) {
    Write-Host ""
    Write-Warning "Simulation terminée. Relancez avec -Forcer après validation de la liste."
}

if ($candidats.Count -eq 0) { exit 0 }
if ($nbErreurs -gt 0) { exit 2 }
exit 1
