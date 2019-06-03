$PSScriptRt = $PSScriptRoot
if ($PSScriptRt.Length -eq 0) {
    $PSScriptRt = (Get-Item -Path .\).FullName
}

Import-Module "$PSScriptRt\Deploy-NavClickOnce.psm1" -Force

$SaveAsDrive = $env:SystemDrive ## Create the folder on user selected Drive Eg. "C:" or "D:"
$DvdOrInstaller = "C:\Dynamics NAV W1 9.0.49424" ## Or "D:" ## Eg. Installer fld "C:\Dynamics NAV W1 9.0" or iso mounted drive "E:" or "G:"
$NavRelease = "RTM" ## RTM or CU1,CU2...
$DeploymentCountryAlpha3Code = "ENU" ## Localization code Eg. ENU,RUS,AU,CHN
$NavVersion = Get-NavVersion -DvdOrInstaller $DvdOrInstaller -ErrorAction Stop

$Server = "NAVAppServer"
$ClientServicesPort = 7046
$TenantId = "Default"
$NavInstanceName = "NAV$NavVersion-W1_$NavRelease" ## Navision Service Instance Eg. "DynamicsNAV90"
$ACSUri = ""
$HelpServer = "NAVHelpServer"
$HelpServerPort = 49000
$ApplicationName = "Dynamics NAV 2016 ClickOnce ($NavRelease)"
$Publisher = "Cronus"
$SupportUrl = "https://Cronus.com/"

$SharedFolderHostName = (Get-WmiObject win32_computersystem).DNSHostName
if (($null -ne (Get-WmiObject win32_computersystem).Domain) -and ('' -ne (Get-WmiObject win32_computersystem).Domain)){
    $SharedFolderHostName += "." + (Get-WmiObject win32_computersystem).Domain ## Use if you have domain
}

$AppWebServer = (Get-WmiObject win32_computersystem).DNSHostName
$WebSiteName = ''
$WebSiteNamePort = 92
$WebSiteHostHeader = (Get-WmiObject win32_computersystem).DNSHostName
if (($null -ne (Get-WmiObject win32_computersystem).Domain) -and ('' -ne (Get-WmiObject win32_computersystem).Domain)){
    $WebSiteHostHeader += "." + (Get-WmiObject win32_computersystem).Domain ## Use if you have domain
}
$WebSiteIPAddress = ''
$WebSiteApplicationPool = ''
$UseSSL = $false

$DeployAsWebHost = $false
$NavClientUserSettingsFile = Join-Path "$PSScriptRt" -ChildPath "Dependency\ClientUserSettings.config"
$UpdateClickOnceDeploy = $false ## Update existing or Create new Clickonce
$ClickOnceCertificate = $false ## Create or Use existing Certificate for Clickonce


$CertOutput = $null
$ClickOnceCertificatePassword = $null
$ClickOnceCertificatePfx = $null
$PlainPassword = ""

if ($ClickOnceCertificate){
    $CertOutput = Join-Path -Path $PSScriptRt -ChildPath "Certificates\$NavInstanceName"
    $ClickOnceCertificatePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
    $ClickOnceCertificatePfx = Get-ClickOnceCertificatePfx -Path $CertOutput


    if (($null -eq $ClickOnceCertificatePfx) -or ('' -eq $ClickOnceCertificatePfx)) {
        $ClickOnceCertificatePfx = New-ClickOnceCertificate -CNName $Publisher -CertOutput $CertOutput -PrivateKeyPassword $ClickOnceCertificatePassword -Validfor 5 `
            -ErrorAction Stop
    }
}

Update-NavClientUserSettings -NavClientUserSettingsFile $NavClientUserSettingsFile -Server $Server -ClientServicesPort $ClientServicesPort `
    -TenantId $TenantId -ServerInstance $NavInstanceName -ClientServicesCredentialType Windows -ACSUri $ACSUri `
    -HelpServer $HelpServer -HelpServerPort $HelpServerPort


if ($UpdateClickOnceDeploy) {
    Update-ClickOnceDeploy -SaveAsDrive $SaveAsDrive -DvdOrInstaller $DvdOrInstaller -NavInstanceName $NavInstanceName -NavClientUserSettingsFile $NavClientUserSettingsFile `
        -ApplicationName $ApplicationName -Version $NavVersion -Publisher $Publisher -SupportUrl $SupportUrl `
        -ClickOnceCertificatePfx $ClickOnceCertificatePfx -ClickOnceCertificatePassword $ClickOnceCertificatePassword `
        -DeploymentCountryAlpha3Code $DeploymentCountryAlpha3Code `
        -WebServerName $AppWebServer -WebSiteNamePort $WebSiteNamePort `
        -UseSSL:$UseSSL -DeployAsWebHost:$DeployAsWebHost
}
else {
    if ($DeployAsWebHost) {
        New-ClickOnceDeploy -SaveAsDrive $SaveAsDrive -DvdOrInstaller $DvdOrInstaller -NavInstanceName $NavInstanceName -NavClientUserSettingsFile $NavClientUserSettingsFile `
            -ApplicationName $ApplicationName -Publisher $Publisher -SupportUrl $SupportUrl `
            -ClickOnceCertificatePfx $ClickOnceCertificatePfx -ClickOnceCertificatePassword $ClickOnceCertificatePassword `
            -DeploymentCountryAlpha3Code $DeploymentCountryAlpha3Code -ShareAs WebShare `
            -SharedFolderHostName $SharedFolderHostName `
            -WebServerName $AppWebServer -WebSiteName $WebSiteName -WebSiteNamePort $WebSiteNamePort `
            -WebSiteHostHeader $WebSiteHostHeader -WebSiteIPAddress $WebSiteIPAddress -WebSiteApplicationPool $WebSiteApplicationPool `
            -UseSSL:$UseSSL -DeployAsWebHost:$DeployAsWebHost -OpenPageOrFolder
    }
    else {
        New-ClickOnceDeploy -SaveAsDrive $SaveAsDrive -DvdOrInstaller $DvdOrInstaller -NavInstanceName $NavInstanceName -NavClientUserSettingsFile $NavClientUserSettingsFile `
            -ApplicationName $ApplicationName -Publisher $Publisher -SupportUrl $SupportUrl `
            -ClickOnceCertificatePfx $ClickOnceCertificatePfx -ClickOnceCertificatePassword $ClickOnceCertificatePassword `
            -DeploymentCountryAlpha3Code $DeploymentCountryAlpha3Code -ShareAs FileShare `
            -SharedFolderHostName $SharedFolderHostName `
            -WebServerName $AppWebServer -WebSiteName $WebSiteName -WebSiteNamePort $WebSiteNamePort `
            -WebSiteHostHeader $WebSiteHostHeader -WebSiteIPAddress $WebSiteIPAddress -WebSiteApplicationPool $WebSiteApplicationPool `
            -UseSSL:$UseSSL -DeployAsWebHost:$DeployAsWebHost -OpenPageOrFolder
    }
}