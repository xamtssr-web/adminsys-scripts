<#
.SYNOPSIS
    Rapport de conformité des correctifs sur un parc Windows.

.DESCRIPTION
    Répond à la question que pose tout audit : « les machines sont-elles à
    jour, et depuis quand n'ont-elles pas redémarré ? »

    Pour chaque machine, le script relève : version et build du système,
    correctifs installés et date du dernier, mises à jour encore en attente
    (via l'API Windows Update en local), indicateurs de redémarrage en
    attente (CBS, Windows Update, renommage de fichiers différé, SCCM),
    état des signatures Defender, et date du dernier démarrage.

    Sortie lisible par un humain, objets exploitables dans un pipeline, export
    CSV pour le reporting. Les codes retour permettent de l'intégrer à une
    supervision ou à une tâche planifiée qui alerte.

.PARAMETER ComputerName
    Machine(s) à interroger. Par défaut la machine locale. Les machines
    distantes nécessitent WinRM (accès CIM/WMI) ; l'analyse des mises à jour
    en attente via l'API Windows Update n'est fiable qu'en local — le script
    l'indique explicitement pour les machines distantes au lieu de mentir.

.PARAMETER JoursRetardMax
    Nombre de jours au-delà duquel une machine est considérée en retard de
    correctifs (défaut : 35, soit un cycle mensuel avec marge).

.PARAMETER ExporterCsv
    Chemin d'export du rapport détaillé.

.PARAMETER ProblemesSeulement
    N'affiche que les machines non conformes — utile pour un envoi automatique.

.EXAMPLE
    .\Get-PatchComplianceReport.ps1

    Rapport de conformité de la machine locale.

.EXAMPLE
    .\Get-PatchComplianceReport.ps1 -ComputerName SRV-DC1, SRV-FIC1 -ExporterCsv .\correctifs.csv

    Rapport sur deux serveurs, exporté pour le reporting mensuel.

.EXAMPLE
    .\Get-PatchComplianceReport.ps1 -ProblemesSeulement -JoursRetardMax 60 | Format-Table

    Uniquement les machines en retard de plus de 60 jours.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : PowerShell 5.1+ ou 7+. WinRM pour les machines distantes.
                  Droits de lecture sur les machines interrogées.
    Version     : 1.0
    Codes retour: 0 = parc conforme
                  1 = au moins un avertissement (redémarrage en attente, signatures anciennes)
                  2 = au moins une machine en retard de correctifs
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [ValidateRange(7, 3650)]
    [int]$JoursRetardMax = 35,

    [Parameter(Mandatory = $false)]
    [string]$ExporterCsv,

    [Parameter(Mandatory = $false)]
    [switch]$ProblemesSeulement
)

begin {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $rapport = [System.Collections.Generic.List[object]]::new()
    $machineLocale = $env:COMPUTERNAME

    # Indicateurs de redémarrage en attente, par lecture du registre
    $clesRedemarrage = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
    )

    function Get-Anciennete {
        param([datetime]$Date)
        if (-not $Date) { return $null }
        return [math]::Round(((Get-Date) - $Date).TotalDays, 0)
    }
}

process {
    foreach ($machine in $ComputerName) {
        Write-Verbose "Analyse de $machine"

        $estLocale = ($machine -eq $machineLocale -or $machine -in @('localhost', '127.0.0.1', '.'))
        $resultat = [ordered]@{
            Machine                 = $machine
            Accessible              = $false
            Systeme                 = $null
            Version                 = $null
            DernierCorrectif        = $null
            JoursDepuisCorrectif    = $null
            NbCorrectifs            = $null
            MajEnAttente            = $null
            RedemarrageEnAttente    = $null
            MotifRedemarrage        = $null
            SignaturesDefenderJours = $null
            DernierDemarrage        = $null
            Statut                  = 'INCONNU'
            Commentaire             = $null
        }

        try {
            if ($estLocale) {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                $correctifs = Get-HotFix

                # Mises à jour en attente via l'API Windows Update (local uniquement)
                $majEnAttente = $null
                try {
                    $session = New-Object -ComObject Microsoft.Update.Session
                    $chercheur = $session.CreateUpdateSearcher()
                    $resultatRecherche = $chercheur.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                    $majEnAttente = $resultatRecherche.Updates.Count
                }
                catch {
                    Write-Verbose "Recherche Windows Update indisponible : $($_.Exception.Message)"
                }

                # Redémarrage en attente : plusieurs sources possibles
                $motifs = @()
                foreach ($cle in $clesRedemarrage) {
                    if (Test-Path $cle) { $motifs += (Split-Path $cle -Leaf) }
                }
                $renommage = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                    -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
                if ($renommage) { $motifs += 'PendingFileRename' }
                $sccm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SCCM\Client\RebootPending' -ErrorAction SilentlyContinue
                if ($sccm) { $motifs += 'SCCM' }

                # Signatures Defender
                $joursSignatures = $null
                try {
                    $signatures = Get-MpComputerStatus -ErrorAction Stop
                    $joursSignatures = Get-Anciennete -Date $signatures.AntivirusSignatureLastUpdated
                }
                catch {
                    Write-Verbose "Défender non interrogeable sur $machine"
                }
            }
            else {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $machine
                $correctifs = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $machine
                $majEnAttente = 'non évalué (à distance)'
                $motifs = @()
                $joursSignatures = $null

                # Le redémarrage en attente se lit aussi à distance
                $renommage = Invoke-Command -ComputerName $machine -ScriptBlock {
                    Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                        -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue
                if ($renommage) { $motifs += 'PendingFileRename' }
            }

            $resultat.Accessible = $true
            $resultat.Systeme = $os.Caption
            $resultat.Version = $os.Version
            $resultat.DernierDemarrage = $os.LastBootUpTime
            $resultat.NbCorrectifs = @($correctifs).Count

            # Correctif le plus récent
            $dates = @($correctifs | Where-Object { $_.InstalledOn } | ForEach-Object { $_.InstalledOn })
            if ($dates.Count -gt 0) {
                $plusRecent = ($dates | Sort-Object -Descending)[0]
                $resultat.DernierCorrectif = $plusRecent
                $resultat.JoursDepuisCorrectif = Get-Anciennete -Date $plusRecent
            }

            $resultat.MajEnAttente = $majEnAttente
            $resultat.RedemarrageEnAttente = ($motifs.Count -gt 0)
            $resultat.MotifRedemarrage = ($motifs -join ', ')
            $resultat.SignaturesDefenderJours = $joursSignatures

            # --- Évaluation du statut ---
            $problemes = @()
            if ($null -ne $resultat.JoursDepuisCorrectif -and $resultat.JoursDepuisCorrectif -gt $JoursRetardMax) {
                $problemes += "aucun correctif depuis $($resultat.JoursDepuisCorrectif) jours"
            }
            if ($resultat.RedemarrageEnAttente) {
                $problemes += "redémarrage en attente ($($resultat.MotifRedemarrage))"
            }
            if ($majEnAttente -is [int] -and $majEnAttente -gt 0) {
                $problemes += "$majEnAttente mise(s) à jour en attente"
            }
            if ($null -ne $joursSignatures -and $joursSignatures -gt 3) {
                $problemes += "signatures antivirus datant de $joursSignatures jours"
            }

            if ($problemes.Count -eq 0) {
                $resultat.Statut = 'CONFORME'
            }
            elseif ($null -ne $resultat.JoursDepuisCorrectif -and $resultat.JoursDepuisCorrectif -gt $JoursRetardMax) {
                $resultat.Statut = 'RETARD'
            }
            else {
                $resultat.Statut = 'ATTENTION'
            }
            $resultat.Commentaire = ($problemes -join ' ; ')
        }
        catch {
            $resultat.Statut = 'INJOIGNABLE'
            $resultat.Commentaire = $_.Exception.Message
        }

        $objet = [pscustomobject]$resultat
        $rapport.Add($objet)

        if (-not $ProblemesSeulement -or $objet.Statut -ne 'CONFORME') {
            $couleur = switch ($objet.Statut) {
                'CONFORME'   { 'Green' }
                'ATTENTION'  { 'Yellow' }
                'RETARD'     { 'Red' }
                default      { 'DarkGray' }
            }
            Write-Host ("  [{0,-11}] {1}" -f $objet.Statut, $objet.Machine) -ForegroundColor $couleur
            if ($objet.Statut -ne 'CONFORME') {
                Write-Host ("               {0}" -f $objet.Commentaire) -ForegroundColor $couleur
            }
            else {
                Write-Host ("               dernier correctif il y a $($objet.JoursDepuisCorrectif) jour(s), à jour") -ForegroundColor DarkGray
            }
        }
    }
}

end {
    $nbRetard = @($rapport | Where-Object Statut -eq 'RETARD').Count
    $nbAttention = @($rapport | Where-Object Statut -eq 'ATTENTION').Count
    $nbInjoignable = @($rapport | Where-Object Statut -eq 'INJOIGNABLE').Count
    $nbConforme = @($rapport | Where-Object Statut -eq 'CONFORME').Count

    Write-Host ""
    Write-Host "================ BILAN ================" -ForegroundColor White
    Write-Host ("  Machines analysées : {0}" -f $rapport.Count)
    Write-Host ("  Conformes          : {0}" -f $nbConforme) -ForegroundColor Green
    if ($nbAttention)  { Write-Host ("  Avertissements     : {0}" -f $nbAttention) -ForegroundColor Yellow }
    if ($nbRetard)     { Write-Host ("  En retard          : {0}" -f $nbRetard) -ForegroundColor Red }
    if ($nbInjoignable){ Write-Host ("  Injoignables       : {0}" -f $nbInjoignable) -ForegroundColor DarkGray }

    if ($ExporterCsv) {
        $rapport | Export-Csv -Path $ExporterCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
        Write-Host ("`nRapport exporté : {0}" -f $ExporterCsv)
    }

    # Sortie exploitable dans un pipeline
    $rapport | Where-Object { $_.Statut -ne 'CONFORME' }

    if ($nbRetard -gt 0 -or $nbInjoignable -gt 0) { exit 2 }
    if ($nbAttention -gt 0) { exit 1 }
    exit 0
}
