#
# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
$ErrorActionPreference = "Stop"

Import-Module ADCharmUtils
Import-Module JujuLogging
Import-Module JujuHelper
Import-Module JujuWindowsUtils
Import-Module JujuUtils
Import-Module JujuHooks
Import-Module OpenStackCommon

function Get-Vcredist {
    Write-JujuWarning "Getting vcredist."
    $vcredistUrl = Get-JujuCharmConfig -Scope "vcredist-url"
    if(!$vcredistUrl) {
        $resourcesSupport = (Get-Command resource-get.exe -ErrorAction SilentlyContinue) -ne $null
        if($resourcesSupport) {
            Write-JujuWarning "Getting Juju resource for vcredist-x64"
            $vcredistPath = Start-ExecuteWithRetry -ScriptBlock { Get-JujuResource -Resource "vcredist-x64" } `
                                                   -RetryMessage "Failed to get vcredist resource. Retrying..."
            return $vcredistPath
        }
        # Fall back to download URL
        $vcredistUrl = $FREE_RDP_VCREDIST
    }
    Write-JujuWarning "Downloading vcredist-x64 from: $vcredistUrl"
    $file = ([System.Uri]$vcredistUrl).Segments[-1]
    $vcredistPath = Join-Path $env:TEMP $file
    Start-ExecuteWithRetry {
        Invoke-FastWebRequest -Uri $vcredistUrl -OutFile $vcredistPath | Out-Null
    } -RetryMessage "Downloading vcredist failed. Retrying..."
    return $vcredistPath
}

function Install-Vcredist {
    Write-JujuWarning "Install vcredist as a prerequisites for FreeRdp"
    $installerPath = Get-Vcredist
    Write-JujuInfo ("Path: {0}" -f $installerPath)
    $ps = Start-Process -Wait -PassThru -FilePath $installerPath `
                        -ArgumentList "/install /passive"
    if ($ps.ExitCode -eq 0) {
        Write-JujuWarning "Finished installing FreeRdp prerequisites"
    } else {
        Throw ("Failed installing FreeRdp prerequisites. Exit code: {0}" -f $ps.ExitCode)
    }
}

function Get-FreeRdpInstaller {
    $installerUrl = Get-JujuCharmConfig -Scope "installer-url"
    if (!$installerUrl) {
        $installerType = 'msi'
        if (Get-IsNanoServer) {
            $installerType = 'zip'
        }
        $resourcesSupport = (Get-Command resource-get.exe -ErrorAction SilentlyContinue) -ne $null
        if($resourcesSupport) {
            Write-JujuWarning "Getting Juju resource for vcredist-x64"
            $installerPath = Start-ExecuteWithRetry -ScriptBlock { Get-JujuResource -Resource "free-rdp-${installerType}-installer" } `
                                                   -RetryMessage "Failed to get Free RDP $installerType installer resource. Retrying..."
            return $installerPath
        }
        # Fall back to download URL
        $installerUrl = $FREE_RDP_INSTALLER[$installerType]
    }
    Write-JujuWarning "Downloading Free RDP installer from: $installerUrl"
    $file = ([System.Uri]$installerUrl).Segments[-1]
    $tempDownloadFile = Join-Path $env:TEMP $file
    Start-ExecuteWithRetry {
        Invoke-FastWebRequest -Uri $installerUrl -OutFile $tempDownloadFile | Out-Null
    } -RetryMessage "Downloading the Free RDP installer failed. Retrying..."
    return $tempDownloadFile
}

function Install-FreeRdp {
    $installerPath = Get-FreeRdpInstaller
    if ($installerPath.EndsWith(".zip")) {
        Install-FreeRdpFromZip -InstallerPath $installerPath
    } elseif ($installerPath.EndsWith(".msi")) {
        Install-FreeRdpFromMSI -InstallerPath $installerPath
    } else {
        $installerExtension = $installerPath.Split('.')[-1]
        Throw ("ERROR: Unknown installer extension: {0}" -f $installerExtension)
    }
    Remove-Item $installerPath
}

function Install-FreeRdpFromMSI {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    Write-JujuWarning "Running FreeRdp installer from msi"
    $hasInstaller = Test-Path $InstallerPath
    if ($hasInstaller -eq $false) {
        $InstallerPath = Get-FreeRdpInstaller
    }

    Write-JujuWarning ("Installing from {0}" -f $InstallerPath)
    $logFile = Join-Path $env:APPDATA "FreeRDP-WebConnect-log.txt"
    $extraParams = @("/n")
    Install-Msi -Installer $InstallerPath -LogFilePath $logFile -ExtraArgs $extraParams
    Write-JujuWarning "FreeRdp was installed from msi"

    # Delete the Windows services created by default by the MSI,
    # so the charm can create them later on.
    Remove-WindowsServices -Names @($FREE_RDP_SERVICE_NAME)
}

function Install-FreeRdpFromZip {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    Write-JujuWarning "Running FreeRdp installer from zip"
    if ((Test-Path $FREE_RDP_INSTALL_DIR)) {
        Remove-Item -Recurse -Force $FREE_RDP_INSTALL_DIR
    }

    Write-JujuWarning ("Unzipping {0} to {1}" -f @($InstallerPath, $FREE_RDP_INSTALL_DIR))
    Expand-ZipArchive -ZipFile $InstallerPath -Destination $FREE_RDP_INSTALL_DIR
    $configDir = Join-Path $FREE_RDP_INSTALL_DIR "etc"
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory $configDir
    }
    Add-ToSystemPath -Path ("{0}\Binaries" -f $FREE_RDP_INSTALL_DIR)
    Write-JujuWarning "Finished running FreeRdp installer from zip"
}

function Get-CharmConfigContext {
    $required = @(
            'tenant-username',
            'http-port',
            'https-port',
            'http-listening-address',
            'https-listening-address',
            'redirect-http-to-https',
            'change-hostname'
        )

    $config = Get-JujuCharmConfig
    $ctxt = Get-ConfigContext

    $missingOptions = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    foreach ($key in $required) {
        if ($config[$key] -eq $null) {
            $missingOptions.Add($key)
        }
    }
    if ($missingOptions.Count -gt 0) {
        $msg = ("Missing required config options: {0}" -f ($missingOptions -Join ", "))
        Set-JujuStatus -Status blocked -Message $msg
        Throw $msg
    }

    $ctxt['document_root'] = "$FREE_RDP_DOCUMENT_ROOT"
    $ctxt['cert_file'] = "$FREE_RDP_CERT_FILE"

    return $ctxt
}

function Get-KeystoneContext {
    $requiredCtx = @{
        "credentials_project_id" = $null
        "credentials_project" = $null
        "credentials_host" = $null
        "credentials_port" = $null
        "credentials_protocol" = $null
        "credentials_username" = $null
        "credentials_password" = $null
        "api_version" = $null
    }

    $ctxt = Get-JujuRelationContext -Relation "identity-credentials" -RequiredContext $requiredCtx
    if (!$ctxt.Count) {
        return @{}
    }

    if ($ctxt["api_version"] -eq 2) {
        $ctxt["keystone_api_version"] = "v2.0"
    } else {
        $ctxt["keystone_api_version"] = "v{0}" -f @($ctxt['api_version'])
    }

    $authurl = "{0}://{1}:{2}/{3}" -f @(
                            $ctxt['credentials_protocol'],
                            $ctxt['credentials_host'],
                            $ctxt['credentials_port'],
                            $ctxt['keystone_api_version']
                        )

    return @{
        'auth_url' = $authurl
        'project_id' = $ctxt['credentials_project_id']
        'project_username' = $ctxt['credentials_username']
        'project_password' = $ctxt['credentials_password']
        'keystone_api_version' = $ctxt['keystone_api_version']
    }
}

function Get-CharmServices {
    $ctxtGenerators = @(
        @{
            "generator" = (Get-Item "function:Get-KeystoneContext").ScriptBlock
            "relation" = "identity-credentials"
            "mandatory" = $true
        },
        @{
            "generator" = (Get-Item "function:Get-CharmConfigContext").ScriptBlock
            "relation" = "config"
            "mandatory" = $true
        },
        @{
            "generator" = (Get-Item "function:Get-ActiveDirectoryContext").ScriptBlock
            "relation" = "ad-join"
            "mandatory" = $true
        }
    );

    $jujuCharmServices = @{
        'free-rdp' = @{
            "template" = "wsgate.ini"
            "config" = Join-Path $FREE_RDP_INSTALL_DIR "etc\wsgate.ini"
            "context_generators" = $ctxtGenerators
        }
    }
    return $jujuCharmServices
}

function New-SelfSignedX509Cert() {
    Write-JujuWarning "Generating self signed certificate"

    $opensslCnf = "$env:CHARM_DIR\files\openssl.cnf"
    Write-JujuWarning ("opensslcnf: {0}" -f $opensslCnf)

    $openssl = Join-Path $FREE_RDP_INSTALL_DIR "Binaries\"
    Write-JujuWarning ("openssl: {0}" -f $openssl)
    $ENV:PATH+=";$openssl"
    $key = Join-Path $FREE_RDP_INSTALL_DIR "etc\key.pem"
    $cert = Join-Path $FREE_RDP_INSTALL_DIR "etc\cert.pem"

    Start-ExternalCommand {
        openssl.exe req -x509 -newkey rsa:2048 -keyout $key -out $cert `
        -days 3650 -nodes -config $opensslCnf `
        -subj "/C=RO/ST=Bucharest/L=Bucharest/O=IT/CN=www.example.ro"
    }

    if (!((Test-Path $key) -and (Test-Path $cert))) {
        Throw "openssl failed to execute"
    }

    $serverCert = Join-Path $FREE_RDP_INSTALL_DIR "etc\server.cer"
    New-Item $serverCert -type file

    $content = [System.IO.File]::ReadAllText($cert)
    $content += [System.IO.File]::ReadAllText($key)
    [System.IO.File]::WriteAllText($serverCert, $content)

    Write-JujuWarning "Finished generating self signed certificate"
}

# HOOK FUNCTIONS

function Invoke-InstallHook {
    Write-JujuInfo "Invoke install hook"
    if (!(Get-IsNanoServer)) {
        Install-Vcredist
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true
        } catch {
            # No need to error out the hook if this fails.
            Write-JujuWarning "Failed to disable monitoring: $_"
        }
    } 
    # Set machine to use high performance settings.
    try {
        Set-PowerProfile -PowerProfile Performance
    } catch [Exception] {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set power scheme."
    }
    Start-TimeResync

    $renameReboot = Rename-JujuUnit
    if($renameReboot) {
        Invoke-JujuReboot -Now
    }

    Install-FreeRdp
    Write-JujuInfo "Finished install hook"
}

function Invoke-ConfigChangedHook {
    Write-JujuInfo "Invoke config changed Hook"

    $services = Get-CharmServices
    $incompleteRelations = New-ConfigFile -ContextGenerators $services['free-rdp']['context_generators'] `
                                          -Template $services['free-rdp']['template'] `
                                          -OutFile $services['free-rdp']['config']

    $serverCert = Join-Path $FREE_RDP_INSTALL_DIR "etc\server.cer"
    if (!(Test-Path $serverCert)) {
        New-SelfSignedX509Cert
    }

    if ($incompleteRelations) {
        $msg = "Incomplete relations: {0}" -f @($incompleteRelations -join ', ')
        Set-JujuStatus -Status blocked -Message $msg
        return
    }

    $service = Get-ManagementObject -Class Win32_Service -Filter "name='$FREE_RDP_SERVICE_NAME'"
    $ctx = Get-ActiveDirectoryContext
    if (!$service) {
        Write-JujuWarning ("Creating service {0}" -f @($FREE_RDP_SERVICE_NAME))
        $wsgateExe = Join-Path $FREE_RDP_INSTALL_DIR "Binaries\wsgate.exe"
        $binaryPath = "`"{0}`" --config `"{1}`"" -f @($wsgateExe, $services['free-rdp']['config'])

        New-Service -Name $FREE_RDP_SERVICE_NAME -BinaryPath $binaryPath `
                    -DisplayName "FreeRDP-WebConnect" `
                    -StartupType Automatic `
                    -Credential $ctx["adcredentials"][0]["pscredentials"] `
                    -Confirm:$false
        Start-ExternalCommand { sc.exe failure $FREE_RDP_SERVICE_NAME reset=5 actions=restart/1000 }
        Start-ExternalCommand { sc.exe failureflag $FREE_RDP_SERVICE_NAME 1 }
    }
    Grant-PrivilegesOnDomainUser $ctx["adcredentials"][0]["username"]
    Restart-Service $FREE_RDP_SERVICE_NAME

    Write-JujuWarning "Open firewall on http and https ports"
    $httpPort = Get-JujuCharmConfig -Scope "http-port"
    $httpsPort = Get-JujuCharmConfig -Scope "https-port"
    $ports = @{
        "tcp" = @($httpPort, $httpsPort)
        "udp" = @($httpPort, $httpsPort)
    }
    Open-Ports -Ports $ports | Out-Null

    Write-JujuWarning "Everything was good and config was generated"
    Set-JujuStatus -Status active -Message "Unit is ready"
    Write-JujuInfo "Finished config changed Hook"
}

function Invoke-StopHook {
    Write-JujuInfo "Invoke stop Hook"

    if (Get-ComponentIsInstalled -Name $FREE_RDP_PRODUCT_NAME -Exact) {
        Write-JujuWarning ("Uninstalling: {0}" -f $FREE_RDP_PRODUCT_NAME)
        Uninstall-WindowsProduct -Name $FREE_RDP_PRODUCT_NAME
    }

    Remove-WindowsServices -Names @($FREE_RDP_SERVICE_NAME)

    if (Test-Path $FREE_RDP_INSTALL_DIR) {
        Remove-Item -Recurse -Force $FREE_RDP_INSTALL_DIR
    }

    Write-JujuInfo "Finished stop Hook"
}
