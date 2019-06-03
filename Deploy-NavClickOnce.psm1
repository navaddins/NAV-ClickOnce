[void] [System.Reflection.Assembly]::LoadWithPartialName("'Microsoft.VisualBasic")

function Convert-SecureStringtoPlainText {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [securestring] $SecureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $PlainText = $PlainText.Trim()
    return $PlainText
}

function Disable-CapsLock {
    [CmdletBinding()]
    Param
    (
        [switch] $Disable
    )    
    # Creating a WScript.Shell onject 
    $keyBoardObject = New-Object -ComObject WScript.Shell
    $capsLockKeySatus = [System.Windows.Forms.Control]::IsKeyLocked('CapsLock') 
    if (($capsLockKeySatus) -and ($Disable)) {
        $keyBoardObject.SendKeys("{CAPSLOCK}")
        Write-Host "Disable-CapsLock is done" -ForegroundColor Cyan            
    }    
}

function Get-IsProcessActive {
    [CmdletBinding()]
    [OutputType([bool])]
    Param
    (
        [parameter(Mandatory = $true)]
        [int]$Id
    )
    $ProcessActive = $null
    try {
        $ProcessActive = Get-Process -Id $Id -ErrorAction SilentlyContinue
    }
    catch {
        $ProcessActive = $null
    }
    return (-Not [bool]($null -eq $ProcessActive))
}

function Start-Process {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "ProgramPath does not exist"
                }
                return $true
            })]
        [string] $ProgramPath,
        [parameter(Mandatory = $true, Position = 2)]
        [string] $ArgumentList,
        [parameter(Mandatory = $false, Position = 3)]
        [int]$Timeout = 600,
        [parameter(Mandatory = $true, Position = 4)]
        [string] $PvkPwd
    )

    $Timeoutms = $Timeout * 1000
    $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo $ProgramPath
    if ($ArgumentList) {
        $ProcessStartInfo.Arguments = $ArgumentList
    }

    $Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)
    $ProcessId = $Process.Id
    $ProcessName = $Process.Name
    ###$ProcessStartTime = $Process.StartTime
    $ProcessCompleted = $Process.WaitForExit($Timeoutms)

    if ((-Not $ProcessCompleted) -and (Get-IsProcessActive($ProcessId))) {
        Disable-CapsLock -Disable
        Write-Host 'Do not press any key. System will auto fill up the password for you' -ForegroundColor Cyan
        Start-Sleep 2
        Do {
            Start-Sleep 1
            $IsProcessActive = Get-IsProcessActive($ProcessId)
            $ProcessActive = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
            if ($IsProcessActive) {
                [Microsoft.VisualBasic.Interaction]::AppActivate($ProcessId)
                Switch ($ProcessActive.MainWindowTitle.ToLower()) {
                    'create private key password' {
                        [System.Windows.Forms.SendKeys]::SendWait("$PvkPwd{TAB}")
                        [System.Windows.Forms.SendKeys]::SendWait("$PvkPwd{ENTER}")
                    }
                    'enter private key password' {
                        [System.Windows.Forms.SendKeys]::SendWait("$PvkPwd{ENTER}")
                    }
                }
            }
        }While ($ProcessActive.Name -eq $ProcessName)
        $ProcessCompleted = $true
    }
    else {
        $ProcessCompleted = $false
        throw 'Cannot find the active process'
    }
    return $ProcessCompleted
}

function New-ClickOnceCertificate {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [string] $CNName,
        [parameter(Mandatory = $true, Position = 2)]
        [string] $CertOutput,
        [parameter(Mandatory = $true, Position = 3)]
        [securestring] $PrivateKeyPassword,
        [parameter(Mandatory = $false, Position = 4)]
        [datetime] $Validfrom = (Get-Date),
        [parameter(Mandatory = $false, Position = 5)]
        [int] $Validfor = 1
    )

    $PSScriptRt = $PSScriptRoot
    if ($PSScriptRt.Length -eq 0) {
        $PSScriptRt = (Get-Item -Path .\).FullName
    }

    Clear-Host
    New-Item -Path $CertOutput -ItemType Directory -Force | Out-Null
    ###$CertOutput = Join-Path -Path $PSScriptRt -ChildPath "Certificates"

    $MakeCertExeLocation = Join-Path -Path $PSScriptRt -ChildPath "Tools\makecert.exe"
    $Cert2SpcExeLocation = Join-Path -Path $PSScriptRt -ChildPath "Tools\cert2spc.exe"
    $Pvk2PfxExeLocation = Join-Path -Path $PSScriptRt -ChildPath "Tools\pvk2pfx.exe"

    $CertificateName = "ClickOnceSignature_" + (Get-Date).ToString('yyyymmdd_hhmmss')
    $ClickOnceSignatureCer = Join-Path -Path $CertOutput -ChildPath "$CertificateName.cer"
    $ClickOnceSignaturePvk = Join-Path -Path $CertOutput -ChildPath "$CertificateName.pvk"
    $ClickOnceSignatureSpc = Join-Path -Path $CertOutput -ChildPath "$CertificateName.spc"
    $ClickOnceCertificatePfx = Join-Path -Path $CertOutput -ChildPath "$CertificateName.pfx"
    $ClickOnceCertificatePassword = Join-Path -Path $CertOutput -ChildPath "$CertificateName.pwd"

    $StartDate = $Validfrom.Tostring("MM/dd/yyyy")
    $EndDate = ($Validfrom.AddYears($Validfor)).Tostring("MM/dd/yyyy")
    <#
$MakeCertCommand = @"
& "$MakeCertExeLocation" -n `"CN=$CNName`" -sv `"$ClickOnceSignaturePvk`" `"$ClickOnceSignatureCer`"  -b $StartDate -e $EndDate -r
"@
    Invoke-Expression -Command $MakeCertCommand
#>
    $PvkPwd = Convert-SecureStringtoPlainText -SecureString $PrivateKeyPassword
    $MakeCertCommand = "-n `"CN=$CNName`" -sv `"$ClickOnceSignaturePvk`" `"$ClickOnceSignatureCer`"  -b $StartDate -e $EndDate -sky signature -r"
    $Continue = Start-Process -ProgramPath $MakeCertExeLocation -ArgumentList $MakeCertCommand -Timeout 2 -PvkPwd $PvkPwd

    if ($Continue) {
        $Cert2SpcCommand = @"
& "$Cert2SpcExeLocation" `"$ClickOnceSignatureCer`" `"$ClickOnceSignatureSpc`"
"@
        Invoke-Expression -Command $Cert2SpcCommand | Out-Null

        $Pvk2PfxCommand = @"
& "$Pvk2PfxExeLocation" -spc `"$ClickOnceSignatureSpc`" -pvk `"$ClickOnceSignaturePvk`" -pi `"$PvkPwd`" -pfx `"$ClickOnceCertificatePfx`"
"@
        Invoke-Expression -Command $Pvk2PfxCommand | Out-Null
        $PvkPwd | Out-File -FilePath $ClickOnceCertificatePassword -Append -NoNewline | Out-Null

        Write-Host "New-ClickOnceCertificate is done" -ForegroundColor Cyan
        return $ClickOnceCertificatePfx
    }
    return ''
}

function Get-CertificatePfx {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "Pfx File does not exist"
                }
                return $true
            })]
        [string] $PfxFile,
        [parameter(Mandatory = $true, Position = 2)]
        [securestring] $PfxPassword
    )
    $PfxPwd = Convert-SecureStringtoPlainText -SecureString $PfxPassword
    $Certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $Certs.Import($PfxFile, $PfxPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"DefaultKeySet")
    return $Certs    
}

function Get-ClickOnceCertificatePfx {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [string] $Path
    )
    if (Test-Path -Path (Join-Path -Path $Path -ChildPath "*.pfx" )) {
        return (Get-Item -Path (Join-Path -Path $Path -ChildPath "*.pfx" )).FullName
    }
    else {
        return ''
    }
}

function New-WebConfigFile {
    param (
        [parameter(Mandatory = $true)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "Path does not exist"
                }
                return $true
            })]
        [string] $Path
    )

    $XmlFile = Join-Path -Path $Path -ChildPath "web.config"
    $XmlString = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
    <directoryBrowse enabled="false" />
    <staticContent>
        <mimeMap fileExtension=".config" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".tlb" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".olb" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".pdb" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".hh" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".xss" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".xsc" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".stx" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".msc" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".flf" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".rdlc" mimeType="application/x-msdownload" />
        <mimeMap fileExtension=".sln" mimeType="application/x-msdownload" />
</staticContent>
    <security>
        <requestFiltering>
        <fileExtensions>
            <remove fileExtension=".config" />
        </fileExtensions>
        </requestFiltering>
    </security>
        <defaultDocument>
            <files>
                <remove value="default.aspx" />
                <remove value="iisstart.htm" />
                <remove value="index.html" />
                <remove value="index.htm" />
                <remove value="Default.asp" />
                <remove value="Default.htm" />
                <add value="NAVClientInstallation.html" />
            </files>
        </defaultDocument>
    </system.webServer>
</configuration>
"@
    $XmlString | Out-File $XmlFile -Encoding ascii -Force | Out-Null
    Write-Host "web.config file is created at $Path" -ForegroundColor Cyan
}

function New-ClickOnceWebSite {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [string] $WebSiteName,
        [parameter(Mandatory = $true, Position = 2)]
        [int] $WebSitePort,
        [parameter(Mandatory = $true, Position = 3)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "WebSitePhysicalPath does not exist"
                }
                return $true
            })]
        [string] $WebSitePhysicalPath,
        [parameter(Mandatory = $false, Position = 4)]
        [string] $WebSiteHostHeader,
        [parameter(Mandatory = $false, Position = 5)]
        [string] $WebSiteIPAddress = "*",
        [parameter(Mandatory = $false, Position = 6)]
        [string] $WebSiteApplicationPool = 'DefaultAppPool',
        [parameter(Mandatory = $true, Position = 7)]
        [string] $WebApplicationName,
        [parameter(Mandatory = $false, Position = 8)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "WebApplicationPhysicalPath does not exist"
                }
                return $true
            })]
        [string] $WebApplicationPhysicalPath,
        [parameter(Mandatory = $false, Position = 9)]
        [int] $SslFlags = 0,
        [parameter(Position = 10)]
        [switch] $UseSSL
    )

    if (($null -eq $WebSiteIPAddress) -or ('' -eq $WebSiteIPAddress)) {
        $WebSiteIPAddress = '*'
    }

    if (($null -eq $WebSiteApplicationPool) -or ('' -eq $WebSiteApplicationPool)) {
        $WebSiteApplicationPool = 'DefaultAppPool'
    }

    $WebSiteNameExist = (Get-Website | Where-Object Name -EQ $WebSiteName)
    if (($null -eq $WebSiteNameExist) -or ('' -eq $WebSiteNameExist)) {
        New-WebSite -Name $WebSiteName -Port $WebSitePort -HostHeader $WebSiteHostHeader -PhysicalPath $WebSitePhysicalPath `
            -ApplicationPool $WebSiteApplicationPool -IPAddress $WebSiteIPAddress -Ssl:$UseSSL -Force | Out-Null
        Write-Host "$WebSiteName is created" -ForegroundColor Cyan

        New-NetFirewallRule -DisplayName "Allow Inbound Port $WebSitePort for $WebSiteName" -Description $WebSiteName `
            -Direction Inbound -LocalPort $WebSitePort -Protocol Tcp -Action Allow | Out-Null
        Write-Host "Allow Inbound Port $WebSitePort for $WebSiteName website" -ForegroundColor Cyan
    }
    
    New-WebApplication -Name $WebApplicationName -Site $WebSiteName -PhysicalPath $WebApplicationPhysicalPath `
        -ApplicationPool $WebSiteApplicationPool -Force | Out-Null
    Write-Host "$WebApplicationName is created under $WebSiteName website" -ForegroundColor Cyan
}

function New-ClickOnceShareFolder {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [string] $SharedName,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "Path does not exist"
                }
                return $true
            })]
        [string] $Path
    )

    if (-Not (Get-SmbShare | Where-Object Name -EQ $SharedName)) {
        Write-Host "`nFolder is shared to everyone with readonly access" -ForegroundColor Cyan
        New-SmbShare -Name $SharedName -Path $Path  -Description "$SharedName Shared folder" `
            -ReadAccess 'Everyone' -ErrorAction Ignore
        Write-Host "New-ClickOnceShareFolder is done" -ForegroundColor Cyan            
    }
}
function UnBlock-Files {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "Path does not exist"
                }
                return $true
            })]
        [string] $Path
    )
    Get-ChildItem -Path $Path -Recurse -Force | Unblock-File
    Write-Host "UnBlock-Files is done" -ForegroundColor Cyan
}

function Remove-ReadOnly {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "Path does not exist"
                }
                return $true
            })]
        [string] $Path
    )
    Get-ChildItem -Path $Path -Recurse| ForEach-Object {
        if ($_.IsReadOnly) {
            $_.IsReadOnly = $false
        }
    }
    Write-Host "Remove-ReadOnly is done" -ForegroundColor Cyan            
}

function Copy-ClientFilesToApplicationDirectory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "ClientFilesDirectory does not exist"
                }
                return $true
            })]
        [string] $ClientFilesDirectory,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "ApplicationFilesDirectory does not exist"
                }
                return $true
            })]
        [string] $ApplicationFilesDirectory
    )  
    BEGIN {
        Write-Host "Navision RTC Client files are copying from $ClientFilesDirectory to $ApplicationFilesDirectory `n" -ForegroundColor Cyan
    }

    PROCESS {
        $ClientFiles = @('Microsoft.Dynamics.Framework.UI.dll',
            'Microsoft.Dynamics.Framework.UI.Extensibility.dll',
            'Microsoft.Dynamics.Framework.UI.Extensibility.xml',
            'Microsoft.Dynamics.Framework.UI.Navigation.dll',
            'Microsoft.Dynamics.Framework.UI.UX2006.dll',
            'Microsoft.Dynamics.Framework.UI.UX2006.WinForms.dll',
            'Microsoft.Dynamics.Framework.UI.Windows.dll',
            'Microsoft.Dynamics.Framework.UI.WinForms.Controls.dll',
            'Microsoft.Dynamics.Framework.UI.WinForms.DataVisualization.dll',
            'Microsoft.Dynamics.Framework.UI.WinForms.dll',
            'Microsoft.Dynamics.Nav.Client.Builder.dll',
            'Microsoft.Dynamics.Nav.Client.exe',
            'Microsoft.Dynamics.Nav.Client.exe.config',
            'Microsoft.Dynamics.Nav.Client.ServiceConnection.dll',
            'Microsoft.Dynamics.Nav.Client.UI.dll',
            'Microsoft.Dynamics.Nav.Client.WinClient.dll',
            'Microsoft.Dynamics.Nav.Client.WinForms.dll',
            'Microsoft.Dynamics.Nav.Common.Exchange.dll',
            'Microsoft.Dynamics.Nav.DocumentService.dll',
            'Microsoft.Dynamics.Nav.DocumentService.Types.dll',
            'Microsoft.Dynamics.Nav.Language.dll',
            'Microsoft.Dynamics.Nav.OpenXml.dll',
            'Microsoft.Dynamics.Nav.SharePointOnlineDocumentService.dll',
            'Microsoft.Dynamics.Nav.Types.dll',
            'Microsoft.Dynamics.Nav.Types.Report.dll',
            'Microsoft.Dynamics.Nav.Watson.dll',
            'Microsoft.Office.Interop.Excel.dll',
            'Microsoft.Office.Interop.OneNote.dll',
            'Microsoft.Office.Interop.Outlook.dll',
            'Microsoft.Office.Interop.Word.dll',
            'Microsoft.IO.RecyclableMemoryStream.dll',
            'Newtonsoft.Json.dll',
            'Office.dll',
            'RapidStart.ico',
            'System.Collections.Immutable.dll')

        foreach ($ClientFile in $ClientFiles) {
            Copy-Item -Path (Join-Path -Path $ClientFilesDirectory -ChildPath $ClientFile) -Destination $ApplicationFilesDirectory -ErrorAction Ignore -Force
        }
        #Copy Images
        Copy-Item "$ClientFilesDirectory\Images" -Destination "$ApplicationFilesDirectory\Images" -Recurse -ErrorAction Ignore -Force

        # Resource assemblies for all languages and add-ins
        Get-ChildItem -Path $ClientFilesDirectory -Filter "??-*" | Copy-Item -Destination $ApplicationFilesDirectory -Container -Recurse -ErrorAction Ignore -Force
        Get-ChildItem -Path $ClientFilesDirectory -Filter "???-*" | Copy-Item -Destination $ApplicationFilesDirectory -Container -Recurse -ErrorAction Ignore -Force

        # Reporting dependencies
        # Report Viewer
        Get-ChildItem -Path $ClientFilesDirectory -Filter "*ReportViewer*"| Copy-Item -Destination $ApplicationFilesDirectory -ErrorAction Ignore -Force

        # Report Viewer Resources
        Get-ChildItem -Path $ClientFilesDirectory -Filter "??" | Copy-Item -Destination $ApplicationFilesDirectory -Container -Recurse -ErrorAction Ignore -Force

        # Sql Server Types
        Copy-Item "$ClientFilesDirectory\Microsoft.SqlServer.Types.dll" -Destination "$ApplicationFilesDirectory" -ErrorAction Ignore -Force
        Copy-Item "$ClientFilesDirectory\SqlServerNativeBinaries" -Destination "$ApplicationFilesDirectory\SqlServerNativeBinaries" -Recurse -ErrorAction Ignore -Force

        Get-ChildItem -Path $ApplicationFilesDirectory -Filter "???-*" | Get-ChildItem -Filter "CodeViewer" | Remove-Item -Recurse -ErrorAction Ignore -Force
        
        Write-Host "Copy-ClientFilesToApplicationDirectory is done" -ForegroundColor Cyan
        UnBlock-Files -Path $ApplicationFilesDirectory
    }
}

function Copy-ClickOnceTemplateFilesToDeploymentInstanceDirectory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "ClickOnceTemplatePath does not exist"
                }
                return $true
            })]
        [string] $ClickOnceTemplatePath,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "DeploymentInstanceDirectory does not exist"
                }
                return $true
            })]
        [string] $DeploymentInstanceDirectory
    )
    BEGIN {
        Write-Host "ClickOnce Template files are copying from $ClickOnceTemplatePath to $DeploymentInstanceDirectory `n" -ForegroundColor Cyan
    }

    PROCESS {
        Get-ChildItem -Path $ClickOnceTemplatePath | Copy-Item -Destination $DeploymentInstanceDirectory -Container -Recurse -ErrorAction Ignore -Force
        Remove-ReadOnly -Path $DeploymentInstanceDirectory
    }
}

function Copy-ClientUserSettingsFilesToApplicationDirectory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "ClientUserSettingsFile does not exist"
                }
                return $true
            })]
        [string] $ClientUserSettingsFile,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "ApplicationFilesDirectory does not exist"
                }
                return $true
            })]
        [string] $ApplicationFilesDirectory
    )
    BEGIN {
        Write-Host "ClientUserSettings.config file is copying from $ClientUserSettingsFile to $ApplicationFilesDirectory `n" -ForegroundColor Cyan
    }

    PROCESS {
        Copy-Item -Path $ClientUserSettingsFile -Destination $ApplicationFilesDirectory -ErrorAction Ignore -Force
    }
}

function Get-NavProductNo {
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    Write-Error -Message "DvdOrInstaller does not exist"
                }
                return $true
            })]        
        [string] $DvdOrInstaller
    )
    if (-NOT (Test-Path (Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient"))) {
        throw "RoleTailoredClient folder does not exist"
    }

    if (($null -eq (Get-Item (Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient\program files\Microsoft Dynamics NAV\*")).Name) -or
        ('' -eq (Get-Item (Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient\program files\Microsoft Dynamics NAV\*")).Name)) {
        return 0
    }
    else {
        return [int](Get-Item (Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient\program files\Microsoft Dynamics NAV\*")).Name
    }        
}

function Get-NavVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    Write-Error -Message "DvdOrInstaller does not exist"
                }
                return $true
            })]        
        [string] $DvdOrInstaller
    )
    if (-NOT (Test-Path (Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient"))) {
        throw "RoleTailoredClient folder does not exist"
    }
    $NavProductNo = Get-NavProductNo -DvdOrInstaller $DvdOrInstaller
    $ClientExe = Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient\program files\Microsoft Dynamics NAV\$NavProductNo\RoleTailored Client\Microsoft.Dynamics.Nav.Client.exe"
    return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ClientExe).FileVersion
}

function Get-ClickOnceName {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [parameter(Mandatory = $true, Position = 1)]            
        [int] $NavProductNo
    )

    $ClickOnceName = ''
    switch ($NavProductNo) {
        60 {
            $ClickOnceName = "Dynamics NAV 2009 ClickOnce"
        }
        70 {
            $ClickOnceName = "Dynamics NAV 2013 ClickOnce"
        }
        71 {
            $ClickOnceName = "Dynamics NAV 2013R2 ClickOnce"
        }
        80 {
            $ClickOnceName = "Dynamics NAV 2015 ClickOnce"
        }                                
        90 {
            $ClickOnceName = "Dynamics NAV 2016 ClickOnce"
        }
        100 {
            $ClickOnceName = "Dynamics NAV 2017 ClickOnce"
        }
        110 {
            $ClickOnceName = "Dynamics NAV 2018 ClickOnce"
        }
    }
    return $ClickOnceName
}

function Add-ClickOnceFiles {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $SaveAsDrive = $env:SystemDrive,         
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "DvdOrInstaller does not exist"
                }
                return $true
            })]
        [string] $DvdOrInstaller,
        [parameter(Mandatory = $true, Position = 2)]
        [string] $NavInstanceName,
        [parameter(Mandatory = $true, Position = 3)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "NavClientUserSettings File does not exist"
                }
                return $true
            })]
        [string] $NavClientUserSettingsFile,
        [parameter(Position = 4)]
        [switch] $DeployAsWebHost
    )

    $PSScriptRt = $PSScriptRoot
    if ($PSScriptRt.Length -eq 0) {
        $PSScriptRt = (Get-Item -Path .\).FullName
    }

    if (($null -eq $SaveAsDrive) -or ('' -eq $SaveAsDrive)){
        $SaveAsDrive = $env:SystemDrive
    }
    $SaveAsDrive = $SaveAsDrive.Replace(':','');
    $SaveAsDrive = $SaveAsDrive.Replace('\','');
    $SaveAsDrive = $SaveAsDrive + ":";

    $NavProductNo = Get-NavProductNo -DvdOrInstaller $DvdOrInstaller -ErrorAction Stop
    $ClickOnceName = Get-ClickOnceName -NavProductNo $NavProductNo
    $ClickOnceDirectory = ""
    if ($DeployAsWebHost) {
        $ClickOnceDirectory = Join-Path -Path $SaveAsDrive -ChildPath "inetpub\wwwroot\$ClickOnceName\ClickOnce"
    }
    else {
        $ClickOnceDirectory = Join-Path -Path $SaveAsDrive -ChildPath "$ClickOnceName"
    }

    ###$DeploymentCountryAlpha3Code = "ENU"
    $DeploymentCountryAlpha3CodeDirectory = Join-Path -Path $ClickOnceDirectory -ChildPath $DeploymentCountryAlpha3Code

    $DeploymentInstanceName = $NavInstanceName
    $DeploymentInstanceDirectory = Join-Path -Path $DeploymentCountryAlpha3CodeDirectory -ChildPath $DeploymentInstanceName

    $DeploymentDirectoryName = "Deployment"
    $DeploymentDirectory = Join-Path -Path $DeploymentInstanceDirectory -ChildPath $DeploymentDirectoryName

    $ApplicationDirectoryName = "ApplicationFiles"
    $ApplicationFilesDirectory = Join-Path -Path $DeploymentDirectory -ChildPath $ApplicationDirectoryName

    $ClientFilesDirectory = Join-Path -Path $DvdOrInstaller -ChildPath "RoleTailoredClient\program files\Microsoft Dynamics NAV\$NavProductNo\RoleTailored Client"

    if (-Not (Test-Path -Path $ApplicationFilesDirectory)) {
        New-Item -Path $ApplicationFilesDirectory -ItemType Directory -Force | Out-Null
    }

    ### Copy Client Files
    Copy-ClientFilesToApplicationDirectory -ClientFilesDirectory $ClientFilesDirectory -ApplicationFilesDirectory $ApplicationFilesDirectory

    ### Copy Template Files
    $ClickOnceTemplate = Join-Path -Path $DvdOrInstaller -ChildPath "ClickOnceInstallerTools\Program Files\Microsoft Dynamics NAV\$NavProductNo\ClickOnce Installer Tools\TemplateFiles"
    Copy-ClickOnceTemplateFilesToDeploymentInstanceDirectory -ClickOnceTemplatePath $ClickOnceTemplate -DeploymentInstanceDirectory $DeploymentInstanceDirectory

    ### Copy Dependency Files (ClientUserSettings.config,WebConfig.config)
    if ($DeployAsWebHost) {
        New-WebConfigFile -Path $DeploymentInstanceDirectory
    }
    else {
        Remove-Item -Path "$DeploymentInstanceDirectory\NAVClientInstallation.html" -ErrorAction Ignore -Force
    }

    Copy-ClientUserSettingsFilesToApplicationDirectory -ClientUserSettingsFile $NavClientUserSettingsFile `
        -ApplicationFilesDirectory $ApplicationFilesDirectory

    Write-Host "Add-ClickOnceFiles is done..." -ForegroundColor Cyan
}

function Update-NavClientUserSettings {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "NavClientUserSettingsFile does not exist"
                }
                return $true
            })]        
        [string] $NavClientUserSettingsFile,       
        [parameter(Mandatory = $true, Position = 1)]
        [string] $Server,
        [parameter(Mandatory = $true, Position = 2)]
        [int] $ClientServicesPort,
        [parameter(Mandatory = $false, Position = 3)]
        [string] $TenantId = "Default",
        [parameter(Mandatory = $true, Position = 4)]
        [string] $ServerInstance,
        [parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('Windows', 'UserName', 'AccessControlService','NavUserPassword')]
        [string] $ClientServicesCredentialType,
        [parameter(Mandatory = $false, Position = 6)]
        [string] $ACSUri,        
        [parameter(Mandatory = $false, Position = 7)]
        [string] $DnsIdentity,
        [parameter(Mandatory = $false, Position = 8)]
        [string] $HelpServer,
        [parameter(Mandatory = $false, Position = 9)]
        [int] $HelpServerPort = 49000,
        [parameter(Mandatory = $false, Position = 10)]
        [string] $ProductName
    )
    Clear-Host

    $PSScriptRt = $PSScriptRoot
    if ($PSScriptRt.Length -eq 0) {
        $PSScriptRt = (Get-Item -Path .\).FullName
    }
    [xml]$XmlDocument = Get-Content -Path $NavClientUserSettingsFile
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'Server'}
    $updConfig.value = $Server
   
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ClientServicesPort'}
    $updConfig.value = $ClientServicesPort.ToString()

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'TenantId'}
    $updConfig.value = $TenantId

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ServerInstance'}
    $updConfig.value = $ServerInstance
   
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'UrlHistory'}
    $updConfig.value = "$Server`:$ClientServicesPort/$ServerInstance"
    
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ClientServicesCredentialType'}
    $updConfig.value = $ClientServicesCredentialType
    
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ACSUri'}
    $updConfig.value = $ACSUri

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'AllowNtlm'}
    $updConfig.value = "true"
    if ($ClientServicesCredentialType -eq 'Windows'){
        $updConfig.value = "false"
    }

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ServicePrincipalNameRequired'}
    $updConfig.value = "false"
    if ($ClientServicesCredentialType -eq 'Windows'){
        $updConfig.value = "true"
    }

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ServicesCertificateValidationEnabled'}
    $updConfig.value = "false"
    if (($ClientServicesCredentialType -eq 'AccessControlService') -or ($ClientServicesCredentialType -eq 'NavUserPassword')){
        $updConfig.value = "true"
    }

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'DnsIdentity'}
    $updConfig.value = $DnsIdentity
   
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'HelpServer'}
    $updConfig.value = $HelpServer
   
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'HelpServerPort'}
    $updConfig.value = $HelpServerPort.ToString()
   
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'ProductName'}
    $updConfig.value = $ProductName
   
    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'UnknownSpnHint'}
    $updConfig.value = "(net.tcp://$Server`:$ClientServicesPort/$ServerInstance)=NoSpn;"
    if ($ClientServicesCredentialType -eq 'Windows'){
        $updConfig.value = "(net.tcp://$Server`:$ClientServicesPort/$ServerInstance)=Spn;"
    }

    $updConfig = $XmlDocument.configuration.appSettings | Select-Object -ExpandProperty childnodes | Where-Object {$_.key -like 'MaxNoOfXMLRecordsToSend'}
    $updConfig.value = "1048576"

    $XmlDocument.Save($NavClientUserSettingsFile)
    Write-Host "ClientUserSettings.config is updated" -ForegroundColor Cyan
}
function Update-ClickOnceDeploy {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $SaveAsDrive = $env:SystemDrive,        
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "DvdOrInstaller does not exist"
                }
                return $true
            })]        
        [string] $DvdOrInstaller,
        [parameter(Mandatory = $true, Position = 2)]
        [string] $NavInstanceName,
        [parameter(Mandatory = $true, Position = 3)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "NavClientUserSettings File does not exist"
                }
                return $true
            })]
        [string] $NavClientUserSettingsFile,
        [parameter(Mandatory = $true, Position = 4)]
        [string] $ApplicationName,        
        [parameter(Mandatory = $false, Position = 5)]
        [string] $Version,
        [parameter(Mandatory = $false, Position = 6)]
        [string] $Publisher = "",
        [parameter(Mandatory = $false, Position = 7)]
        [string] $SupportUrl = "",
        [parameter(Mandatory = $false, Position = 8)]
        [string] $ClickOnceCertificatePfx,
        [parameter(Mandatory = $false, Position = 9)]
        [securestring] $ClickOnceCertificatePassword,
        [parameter(Mandatory = $false, Position = 10)]
        [string] $DeploymentCountryAlpha3Code,
        [parameter(Mandatory = $false, Position = 11)]
        [string] $WebServerName,
        [parameter(Mandatory = $false, Position = 12)]
        [int] $WebSiteNamePort = 80,
        [parameter(Position = 13)]
        [switch] $UseSSL,
        [parameter(Position = 14)]
        [switch] $DeployAsWebHost
    )

    Clear-Host

    $PSScriptRt = $PSScriptRoot
    if ($PSScriptRt.Length -eq 0) {
        $PSScriptRt = (Get-Item -Path .\).FullName
    }

    if (($null -eq $SaveAsDrive) -or ('' -eq $SaveAsDrive)){
        $SaveAsDrive = $env:SystemDrive
    }
    $SaveAsDrive = $SaveAsDrive.Replace(':','');
    $SaveAsDrive = $SaveAsDrive.Replace('\','');
    $SaveAsDrive = $SaveAsDrive + ":";

    if (($null -ne $ClickOnceCertificatePfx) -and ('' -ne $ClickOnceCertificatePfx)) {
        if (-Not (Test-Path -Path $ClickOnceCertificatePfx)) {
            throw "$ClickOnceCertificatePfx does not exist"
        }

        if (($null -eq $ClickOnceCertificatePassword) -or (0 -eq $ClickOnceCertificatePassword.Length)) {
            throw 'ClickOnceCertificatePfx password cannot be empty'
        }        
        $PfPwd = Convert-SecureStringtoPlainText -SecureString $ClickOnceCertificatePassword        
    }
    
    $MageExeLocation = Join-Path -Path $PSScriptRt -ChildPath "Tools\mage.exe"
    if (-Not (Test-Path -Path $MageExeLocation -PathType Leaf)) {
        throw "Mage.exe does not exist in $MageExeLocation"
    }

    Add-ClickOnceFiles -DvdOrInstaller $DvdOrInstaller -NavInstanceName $NavInstanceName -NavClientUserSettingsFile $NavClientUserSettingsFile `
        -DeployAsWebHost:$DeployAsWebHost -ErrorAction Stop

    $NavProductNo = Get-NavProductNo -DvdOrInstaller $DvdOrInstaller
    $ClickOnceName = Get-ClickOnceName -NavProductNo $NavProductNo

    $ClickOnceDirectory = ""
    if ($DeployAsWebHost) {
        $ClickOnceDirectory = Join-Path -Path $SaveAsDrive -ChildPath "inetpub\wwwroot\$ClickOnceName\ClickOnce"
    }
    else {
        $ClickOnceDirectory = Join-Path -Path $SaveAsDrive -ChildPath "$ClickOnceName"
    }
    
    $DeploymentCountryAlpha3CodeDirectory = Join-Path -Path $ClickOnceDirectory -ChildPath $DeploymentCountryAlpha3Code

    $DeploymentInstanceName = $NavInstanceName
    $DeploymentInstanceDirectory = Join-Path -Path $DeploymentCountryAlpha3CodeDirectory -ChildPath $DeploymentInstanceName

    $DeploymentDirectoryName = "Deployment"
    $DeploymentDirectory = Join-Path -Path $DeploymentInstanceDirectory -ChildPath $DeploymentDirectoryName

    $ApplicationDirectoryName = "ApplicationFiles"
    $ApplicationFilesDirectory = Join-Path -Path $DeploymentDirectory -ChildPath $ApplicationDirectoryName
    $ApplicationFile = Join-Path -Path $DeploymentDirectory -ChildPath "Microsoft.Dynamics.Nav.Client.application"
    $ApplicationManifestFile = Join-Path -Path $ApplicationFilesDirectory -ChildPath "Microsoft.Dynamics.Nav.Client.exe.manifest"

    if (-Not (Test-Path $ApplicationFilesDirectory)) {
        throw "$ApplicationFilesDirectory does not exist"
    }

    if (($null -eq $Version) -or ('' -eq $Version)) {
        $Version = Get-NavVersion -DvdOrInstaller $DvdOrInstaller
    }
    $ProviderUrl = ''
    $LinkAddress = ''
    if ($DeployAsWebHost) {
        if ($WebSiteNamePort -eq 0) {
            $WebSiteNamePort = 80
        }

        if ($UseSSL) {
            $LinkAddress = "https://$WebServerName`:$WebSiteNamePort/ClickOnce/$DeploymentCountryAlpha3Code/$DeploymentInstanceName/"
        }
        else {
            $LinkAddress = "http://$WebServerName`:$WebSiteNamePort/ClickOnce/$DeploymentCountryAlpha3Code/$DeploymentInstanceName/"
        }
        $ProviderUrl = "$LinkAddress/$DeploymentDirectoryName/Microsoft.Dynamics.Nav.Client.application"
    }
    else {
        $LinkAddress = "\\$SharedFolderHostName\$ClickOnceName\$DeploymentCountryAlpha3Code\$DeploymentInstanceName"
        $ProviderUrl = Join-Path -Path $LinkAddress -ChildPath "$DeploymentDirectoryName\Microsoft.Dynamics.Nav.Client.application"
    }
    
    ##Update Microsoft.Dynamics.Nav.Client.exe.manifest
    Write-Host "Update Microsoft.Dynamics.Nav.Client.exe.manifest" -ForegroundColor Cyan
    $ArgumentList = @"
-u `"$ApplicationManifestFile`" -n `"$ApplicationName`" -v $Version -fd `"$ApplicationFilesDirectory`"
"@

    if (($null -ne $Publisher) -and ('' -ne $Publisher)) {
        $ArgumentList = @"
$ArgumentList -pub `"$Publisher`" -um true
"@
    }

    if (($null -ne $SupportUrl) -and ('' -ne $SupportUrl)) {
        $ArgumentList = @"
$ArgumentList -s `"$SupportUrl`"
"@
    }

    $MageCommand = @"
& "$MageExeLocation" $ArgumentList
"@
    Invoke-Expression -Command $MageCommand

    ##Sign Certificate to Microsoft.Dynamics.Nav.Client.exe.manifest
    if ((($null -ne $ClickOnceCertificatePfx) -and ('' -ne $ClickOnceCertificatePfx)) -and
        (($null -ne $ClickOnceCertificatePassword) -and (0 -ne $ClickOnceCertificatePassword.Length))) {
        Write-Host "Sign Certificate to Microsoft.Dynamics.Nav.Client.exe.manifest" -ForegroundColor Cyan
        $ArgumentList = @"
-s `"$ApplicationManifestFile`" -cf `"$ClickOnceCertificatePfx`" -pwd `"$PfPwd`"
"@

        $MageCommand = @"
& "$MageExeLocation" $ArgumentList
"@
        Invoke-Expression -Command $MageCommand
    }
    ##Update Microsoft.Dynamics.Nav.Client.application
    Write-Host "Update Microsoft.Dynamics.Nav.Client.application" -ForegroundColor Cyan
    $ArgumentList = @"
-u `"$ApplicationFile`" -n `"$ApplicationName`" -v $Version -mv $Version -appm `"$ApplicationManifestFile`" -appc "ApplicationFiles\Microsoft.Dynamics.Nav.Client.exe.manifest" -pu `"$ProviderUrl`"
"@

    if (($null -ne $Publisher) -and ('' -ne $Publisher)) {
        $ArgumentList = @"
$ArgumentList -pub `"$Publisher`"
"@
    }

    if (($null -ne $SupportUrl) -and ('' -ne $SupportUrl)) {
        $ArgumentList = @"
$ArgumentList -s `"$SupportUrl`"
"@
    }

    $MageCommand = @"
& "$MageExeLocation" $ArgumentList
"@
    Invoke-Expression -Command $MageCommand

    ##Sign Certificate to Microsoft.Dynamics.Nav.Client.application
    if ((($null -ne $ClickOnceCertificatePfx) -and ('' -ne $ClickOnceCertificatePfx)) -and
        (($null -ne $ClickOnceCertificatePassword) -and (0 -ne $ClickOnceCertificatePassword.Length))) {

        Write-Host "Sign Certificate to Microsoft.Dynamics.Nav.Client.application" -ForegroundColor Cyan
        $ArgumentList = @"
-s `"$ApplicationFile`" -cf `"$ClickOnceCertificatePfx`" -pwd `"$PfPwd`"
"@

        $MageCommand = @"
& "$MageExeLocation" $ArgumentList
"@
        Invoke-Expression -Command $MageCommand
    }    
    Write-Host "Update-ClickOnceDeploy is done..." -ForegroundColor Cyan
    Write-Host "ClickOnce folder is $ClickOnceDirectory" -ForegroundColor Cyan
}

function New-ClickOnceDeploy {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $SaveAsDrive = $env:SystemDrive,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "DvdOrInstaller does not exist"
                }
                return $true
            })]        
        [string] $DvdOrInstaller,
        [parameter(Mandatory = $true, Position = 2)]
        [string] $NavInstanceName,
        [parameter(Mandatory = $true, Position = 3)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "NavClientUserSettings File does not exist"
                }
                return $true
            })]
        [string] $NavClientUserSettingsFile,
        [parameter(Mandatory = $true, Position = 4)]
        [string] $ApplicationName,
        [parameter(Mandatory = $false, Position = 5)]
        [string] $Publisher = "",
        [parameter(Mandatory = $false, Position = 6)]
        [string] $SupportUrl = "",        
        [parameter(Mandatory = $false, Position = 7)]        
        [string] $ClickOnceCertificatePfx,
        [parameter(Mandatory = $false, Position = 8)]
        [securestring] $ClickOnceCertificatePassword,
        [parameter(Mandatory = $false, Position = 9)]
        [string] $DeploymentCountryAlpha3Code,
        [parameter(Mandatory = $false, Position = 10)]
        [ValidateSet('None', 'FileShare', 'WebShare')]
        [string] $ShareAs = 'None',
        [parameter(Mandatory = $false, Position = 11)]
        [string] $SharedFolderHostName,
        [parameter(Mandatory = $false, Position = 12)]
        [string] $WebServerName,
        [parameter(Mandatory = $false, Position = 13)]
        [string] $WebSiteName,
        [parameter(Mandatory = $false, Position = 14)]
        [int] $WebSiteNamePort = 80,
        [parameter(Mandatory = $false, Position = 15)]
        [string] $WebSiteHostHeader = '',
        [parameter(Mandatory = $false, Position = 16)]
        [string] $WebSiteIPAddress = '*',
        [parameter(Mandatory = $false, Position = 17)]
        [string] $WebSiteApplicationPool = 'DefaultAppPool',
        [parameter(Position = 18)]
        [switch] $UseSSL,
        [parameter(Position = 19)]
        [switch] $DeployAsWebHost,
        [parameter(Position = 20)]
        [switch] $OpenPageOrFolder
    )

    Clear-Host    
    $PSScriptRt = $PSScriptRoot
    if ($PSScriptRt.Length -eq 0) {
        $PSScriptRt = (Get-Item -Path .\).FullName
    }

    if (($null -eq $SaveAsDrive) -or ('' -eq $SaveAsDrive)){
        $SaveAsDrive = $env:SystemDrive
    }
    $SaveAsDrive = $SaveAsDrive.Replace(':','');
    $SaveAsDrive = $SaveAsDrive.Replace('\','');
    $SaveAsDrive = $SaveAsDrive + ":";

    $NavProductNo = Get-NavProductNo -DvdOrInstaller $DvdOrInstaller -ErrorAction Stop
    $ClickOnceName = Get-ClickOnceName -NavProductNo $NavProductNo
    
    $ClickOnceDirectory = ""
    if ($DeployAsWebHost) {
        $ClickOnceDirectory = Join-Path -Path $SaveAsDrive -ChildPath "inetpub\wwwroot\$ClickOnceName\ClickOnce"
    }
    else {
        $ClickOnceDirectory = Join-Path -Path $SaveAsDrive -ChildPath "$ClickOnceName"
    }
    $DeploymentInstanceName = $NavInstanceName
    $DeploymentDirectoryName = "Deployment"
    
    switch ($ShareAs.ToLower()) {
        'fileshare' {
            if (-Not ($DeployAsWebHost)) {
                if (($SharedFolderHostName -eq $null) -or ($SharedFolderHostName -eq "")) {
                    throw "Shared Server name cannot be empty"
                }
            }
        }
        'webshare' {
            if ($DeployAsWebHost) {
                if (($null -ne $WebSiteHostHeader) -and ("" -ne $WebSiteHostHeader)) {
                    $WebServerName = $WebSiteHostHeader
                }
                if (($null -eq $WebServerName) -or ("" -eq $WebServerName)) {
                    throw "Web Server name cannot be empty"
                }
            }
        }
    }

    $Version = ''
    ##Update manifest/application
    Update-ClickOnceDeploy -SaveAsDrive $SaveAsDrive -DvdOrInstaller $DvdOrInstaller `
        -NavInstanceName $NavInstanceName -NavClientUserSettingsFile $NavClientUserSettingsFile `
        -ApplicationName $ApplicationName -Version $Version -Publisher $Publisher -SupportUrl $SupportUrl `
        -ClickOnceCertificatePfx $ClickOnceCertificatePfx -ClickOnceCertificatePassword $ClickOnceCertificatePassword `
        -DeploymentCountryAlpha3Code $DeploymentCountryAlpha3Code `
        -WebServerName $WebServerName -WebSiteNamePort $WebSiteNamePort -UseSSL:$UseSSL -DeployAsWebHost:$DeployAsWebHost -ErrorAction Stop

    $LinkAddress = ''
    if ($DeployAsWebHost) {
        if ($WebSiteNamePort -eq 0) {
            if ($UseSSL) {
                $WebSiteNamePort = 443
            }
            else {
                $WebSiteNamePort = 80
            }
        }

        if (($null -eq $WebSiteName) -or ('' -eq $WebSiteName)) {
            $WebSiteName = "Microsoft $ClickOnceName"
        }
        $WebSitePhysicalPath = Join-Path -Path $SaveAsDrive -ChildPath "\inetpub\wwwroot\$ClickOnceName"
        $WebApplicationName = Join-Path -Path "ClickOnce\$DeploymentCountryAlpha3Code" -ChildPath $DeploymentInstanceName
        $WebApplicationPhysicalPath = Join-Path -Path $WebSitePhysicalPath -ChildPath $WebApplicationName

        if ($UseSSL) {
            $LinkAddress = "https://$WebServerName`:$WebSiteNamePort/ClickOnce/$DeploymentCountryAlpha3Code/$DeploymentInstanceName/"
        }
        else {
            $LinkAddress = "http://$WebServerName`:$WebSiteNamePort/ClickOnce/$DeploymentCountryAlpha3Code/$DeploymentInstanceName/"
        }
    }
    else {
        $LinkAddress = "\\$SharedFolderHostName\$ClickOnceName\$DeploymentCountryAlpha3Code\$DeploymentInstanceName"
    }

    switch ($ShareAs.ToLower()) {
        'fileshare' {
            if (-Not ($DeployAsWebHost)) {                
                New-ClickOnceShareFolder -SharedName $ClickOnceName -Path $ClickOnceDirectory
                if ($OpenPageOrFolder) {
                    explorer.exe (Join-Path -Path $LinkAddress -ChildPath $DeploymentDirectoryName)
                }
            }
        }
        'webshare' {
            if ($DeployAsWebHost) {
                New-ClickOnceWebSite -WebSiteName $WebSiteName -WebSitePort $WebSiteNamePort `
                    -WebSitePhysicalPath $WebSitePhysicalPath -WebSiteHostHeader $WebSiteHostHeader -WebSiteIPAddress $WebSiteIPAddress `
                    -WebApplicationName $WebApplicationName -WebApplicationPhysicalPath $WebApplicationPhysicalPath -WebSiteApplicationPool $WebSiteApplicationPool `
                    -SslFlags 0 -UseSSL:$UseSSL
                
                if ($OpenPageOrFolder) {
                    ### Open the website at IE
                    $ie = New-Object -ComObject "InternetExplorer.Application"                    
                    $ie.Navigate($LinkAddress);
                    $ie.Visible = $true;
                }
            }
        }
    }
    Write-Host "New-ClickOnceDeploy is done..." -ForegroundColor Cyan
}

Export-ModuleMember Get-CertificatePfx, Get-ClickOnceCertificatePfx, New-ClickOnceCertificate, New-ClickOnceWebSite, New-ClickOnceShareFolder, Get-NavProductNo, Get-NavVersion, Get-ClickOnceName, Update-NavClientUserSettings, Update-ClickOnceDeploy, New-ClickOnceDeploy