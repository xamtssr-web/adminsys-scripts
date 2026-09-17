<#
.SYNOPSIS
    Inventaire matériel, système et logiciel d'un parc Windows, exportable pour un outil d'inventaire.

.DESCRIPTION
    Collecte en une passe ce qu'on met deux jours à rassembler à la main lors
    d'un audit ou d'une reprise de parc : identité de la machine, système,
    processeur, mémoire, disques, réseau, état de virtualisation, dernier
    démarrage, et — en option — les logiciels installés.

    La sortie est un objet par machine, exportable en CSV (colonnes stables,
    avec point-virgule et encodage UTF-8 pour Excel français) ou en JSON pour
    un outil d'inventaire type GLPI, OCS ou un script d'alimentation CMDB.

    Les logiciels sont lus dans la base de désinstallation du registre, jamais
    via Win32_Product — cette classe WMI déclenche une reconfiguration MSI de
    chaque paquet installé, ce qui peut casser des applications en production.

.PARAMETER ComputerName
    Machine(s) à inventorier. Par défaut la machine locale. Les machines
    distantes nécessitent WinRM et des droits de lecture.

.PARAMETER InclureLogiciels
    Ajoute la liste des logiciels installés (nom, version, éditeur, date) et
    leur nombre. Plus lent : à réserver à l'inventaire complet.

.PARAMETER ExporterCsv
    Export CSV principal (une ligne par machine, colonnes aplaties).

.PARAMETER ExporterJson
    Export JSON détaillé, y compris les listes (disques, cartes réseau,
    logiciels) — format attendu par la plupart des outils d'inventaire.

.PARAMETER DossierLogiciels
    Dossier de sortie d'un CSV séparé par machine listant les logiciels.

.EXAMPLE
    .\Get-InfrastructureInventory.ps1

    Inventaire de la machine locale, affiché à l'écran.

.EXAMPLE
    .\Get-InfrastructureInventory.ps1 -ComputerName SRV-FIC1, SRV-APP1 `
        -InclureLogiciels -ExporterCsv .\parc.csv -ExporterJson .\parc.json

    Inventaire complet de deux serveurs, logiciels inclus, exporté pour la CMDB.

.EXAMPLE
    Get-Content .\machines.txt | .\Get-InfrastructureInventory.ps1 -ExporterCsv .\parc.csv

    Inventaire d'une liste de machines lue depuis un fichier.

.NOTES
    Auteur      : Massounde CHAMSIDINE
    Prérequis   : PowerShell 5.1+ ou 7+ (Windows). WinRM pour l'inventaire distant.
    Version     : 1.0
    Codes retour: 0 = inventaire complet
                  1 = inventaire partiel (au moins une machine injoignable)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [switch]$InclureLogiciels,

    [Parameter(Mandatory = $false)]
    [string]$ExporterCsv,

    [Parameter(Mandatory = $false)]
    [string]$ExporterJson,

    [Parameter(Mandatory = $false)]
    [string]$DossierLogiciels
)

begin {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $inventaire = [System.Collections.Generic.List[object]]::new()
    $logicielsParMachine = @{}
    $nbInjoignables = 0
    $machineLocale = $env:COMPUTERNAME

    function ConvertTo-Go {
        <# Convertit des octets en gigaoctets arrondis. #>
        param($Octets)
        if (-not $Octets) { return 0 }
        return [math]::Round($Octets / 1GB, 1)
    }
}

process {
    foreach ($machine in $ComputerName) {
        Write-Verbose "Inventaire de $machine"
        $estLocale = ($machine -eq $machineLocale -or $machine -in @('localhost', '127.0.0.1', '.'))

        # Jeu de paramètres CIM commun (vide pour la machine locale)
        $cim = @{}
        if (-not $estLocale) { $cim['ComputerName'] = $machine }

        $donnees = [ordered]@{
            Nom                  = $machine
            Joignable            = $false
            Constructeur         = $null
            Modele               = $null
            NumeroDeSerie        = $null
            TypeMachine          = $null
            Systeme              = $null
            VersionSysteme       = $null
            Architecture         = $null
            Processeur           = $null
            CoeursPhysiques      = $null
            CoeursLogiques       = $null
            MemoireGo            = $null
            BaretttesUtilisees   = $null
            Disques              = $null
            EspaceTotalGo        = $null
            EspaceLibreGo        = $null
            CartesReseau         = $null
            AdressesIP           = $null
            AdressesMAC          = $null
            Domaine              = $null
            UtilisateurConnecte  = $null
            DernierDemarrage     = $null
            DisponibiliteJours   = $null
            NbLogiciels          = $null
            VersionBIOS          = $null
            Statut               = 'INCONNU'
            Commentaire          = $null
        }

        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem @cim
            $os = Get-CimInstance -ClassName Win32_OperatingSystem @cim
            $bios = Get-CimInstance -ClassName Win32_BIOS @cim -ErrorAction SilentlyContinue
            $cpu = Get-CimInstance -ClassName Win32_Processor @cim -ErrorAction SilentlyContinue
            $disquesLogiques = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' @cim -ErrorAction SilentlyContinue)
            $cartes = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' @cim -ErrorAction SilentlyContinue)

            # Détection de la virtualisation : le fabricant du système est le signal
            # le plus fiable pour distinguer une VM d'une machine physique.
            $typeMachine = 'Physique'
            if ($cs.Model -match 'Virtual|VMware|KVM|Hyper-V|QEMU|Xen|Bochs') { $typeMachine = 'Virtuelle' }
            if ($cs.Manufacturer -match 'VMware|Microsoft Corporation|QEMU|innotek|Xen|Amazon') { $typeMachine = 'Virtuelle' }

            $donnees.Joignable = $true
            $donnees.Constructeur = $cs.Manufacturer
            $donnees.Modele = $cs.Model
            $donnees.NumeroDeSerie = if ($bios) { $bios.SerialNumber } else { $null }
            $donnees.TypeMachine = $typeMachine
            $donnees.Systeme = $os.Caption
            $donnees.VersionSysteme = $os.Version
            $donnees.Architecture = $os.OSArchitecture
            $donnees.Processeur = if ($cpu) { ($cpu | Select-Object -First 1).Name } else { $null }
            $donnees.CoeursPhysiques = if ($cpu) { ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum } else { $null }
            $donnees.CoeursLogiques = if ($cpu) { ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum } else { $null }
            $donnees.MemoireGo = ConvertTo-Go $cs.TotalPhysicalMemory
            $donnees.VersionBIOS = if ($bios) { $bios.SMBIOSBIOSVersion } else { $null }

            try {
                $barettes = @(Get-CimInstance -ClassName Win32_PhysicalMemory @cim -ErrorAction SilentlyContinue)
                $donnees.BarettesUtilisees = if ($barettes.Count -gt 0) { $barettes.Count } else { $null }
            }
            catch {
                Write-Verbose "Emplacements mémoire non lisibles sur $machine"
            }

            $donnees.Disques = ($disquesLogiques | ForEach-Object {
                "{0} {1} Go dont {2} Go libres" -f $_.DeviceID, (ConvertTo-Go $_.Size), (ConvertTo-Go $_.FreeSpace)
            }) -join ' | '
            $donnees.EspaceTotalGo = ConvertTo-Go (($disquesLogiques | Measure-Object -Property Size -Sum).Sum)
            $donnees.EspaceLibreGo = ConvertTo-Go (($disquesLogiques | Measure-Object -Property FreeSpace -Sum).Sum)
            $donnees.CartesReseau = ($cartes | ForEach-Object { $_.Description }) -join ' | '
            $donnees.AdressesIP = ($cartes | ForEach-Object { $_.IPAddress } | Where-Object { $_ }) -join ', '
            $donnees.AdressesMAC = ($cartes | ForEach-Object { $_.MACAddress } | Where-Object { $_ }) -join ', '
            $donnees.Domaine = $cs.Domain
            $donnees.UtilisateurConnecte = $cs.UserName
            $donnees.DernierDemarrage = $os.LastBootUpTime

            if ($os.LastBootUpTime) {
                $donnees.DisponibiliteJours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
            }

            # --- Logiciels installés (base de désinstallation, pas Win32_Product) ---
            if ($InclureLogiciels) {
                $logiciels = @()
                if ($estLocale) {
                    $chemins = @(
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    )
                    $logiciels = Get-ItemProperty -Path $chemins -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                        Sort-Object DisplayName
                }
                else {
                    $logiciels = Invoke-Command -ComputerName $machine -ScriptBlock {
                        Get-ItemProperty -Path @(
                            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                        ) -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName } |
                            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                            Sort-Object DisplayName
                    } -ErrorAction SilentlyContinue
                }

                $logicielsParMachine[$machine] = $logiciels
                $donnees.NbLogiciels = @($logiciels).Count
            }

            $donnees.Statut = 'INVENTORIE'
        }
        catch {
            $donnees.Statut = 'INJOIGNABLE'
            $donnees.Commentaire = ($_.Exception.Message -split "`n")[0]
            $nbInjoignables++
        }

        $objet = [pscustomobject]$donnees
        $inventaire.Add($objet)

        $couleur = if ($objet.Statut -eq 'INVENTORIE') { 'Green' } else { 'Red' }
        Write-Host ("  [{0,-11}] {1}" -f $objet.Statut, $objet.Nom) -ForegroundColor $couleur
        if ($objet.Statut -eq 'INVENTORIE') {
            Write-Host ("               {0} {1} — {2} — {3} Go RAM — {4} Go libres{5}" -f `
                $objet.Constructeur, $objet.Modele, $objet.Systeme, $objet.MemoireGo, `
                $objet.EspaceLibreGo, $(if ($objet.NbLogiciels) { " — $($objet.NbLogiciels) logiciels" } else { '' })) -ForegroundColor DarkGray
        }
        else {
            Write-Host ("               {0}" -f $objet.Commentaire) -ForegroundColor Red
        }
    }
}

end {
    Write-Host ""
    Write-Host "================ BILAN ================" -ForegroundColor White
    Write-Host ("  Machines inventoriées : {0}" -f @($inventaire | Where-Object Joignable).Count)
    if ($nbInjoignables) {
        Write-Host ("  Injoignables          : {0}" -f $nbInjoignables) -ForegroundColor Red
    }

    if ($ExporterCsv) {
        $inventaire | Export-Csv -Path $ExporterCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
        Write-Host ("`nInventaire CSV  : {0}" -f $ExporterCsv)
    }

    if ($ExporterJson) {
        $inventaire | ConvertTo-Json -Depth 4 | Set-Content -Path $ExporterJson -Encoding UTF8
        Write-Host ("Inventaire JSON : {0}" -f $ExporterJson)
    }

    if ($DossierLogiciels) {
        if (-not (Test-Path $DossierLogiciels)) {
            New-Item -Path $DossierLogiciels -ItemType Directory -Force | Out-Null
        }
        foreach ($machine in $logicielsParMachine.Keys) {
            $chemin = Join-Path $DossierLogiciels ("logiciels-" + ($machine -replace '[^A-Za-z0-9\-]', '_') + ".csv")
            $logicielsParMachine[$machine] | Export-Csv -Path $chemin -NoTypeInformation -Delimiter ';' -Encoding UTF8
            Write-Host ("Logiciels        : {0}" -f $chemin)
        }
    }

    $inventaire
    if ($nbInjoignables -gt 0) { exit 1 }
    exit 0
}
