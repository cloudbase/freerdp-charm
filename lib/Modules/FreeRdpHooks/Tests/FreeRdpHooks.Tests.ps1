$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}

Import-Module FreeRdpHooks

InModuleScope FreeRdpHooks {
    Describe "Start-InstallHook" {
        Context "Is not Nano and change hostname is true" {
            Mock Get-IsNanoServer { return $false } -Verifiable
            Mock Install-Vcredist {} -Verifiable
            Mock Set-MpPreference {} -Verifiable
            Mock Write-JujuWarning {} -Verifiable
            Mock Set-PowerProfile {} -Verifiable
            Mock Start-TimeResync {} -Verifiable
            Mock Convert-JujuUnitNameToNetbios { return "whatever" } -Verifiable
            Mock Get-CharmState { return $false } -Verifiable
            Mock Get-JujuCharmConfig { return $true } -Verifiable
            Mock Set-CharmState {} -Verifiable
            Mock Rename-Computer {} -Verifiable
            Mock Invoke-JujuReboot {} -Verifiable
            Mock Install-FreeRdp {} -Verifiable
            Mock Get-CharmServices { return @{"free-rdp" = @{"service" = "whatever"}} } -Verifiable
            Mock Get-ManagementObject { return $false } -Verifiable

            Start-InstallHook

            It "Should call Convert-JujuUnitNameToNetbios one time" {
                Assert-MockCalled Convert-JujuUnitNameToNetbios -Exactly 1
            }

            It "Should call Start-TimeResync one time" {
                Assert-MockCalled Start-TimeResync -Exactly 1
            }

            It "Should call Get-CharmState one time" {
                Assert-MockCalled Get-CharmState -Exactly 1 -ParameterFilter {
                    ($Namespace -eq "Common") -and
                    ($Key -eq "HostnameChanged")
                }
            }

            It "Should call Get-JujuCharmConfig one time" {
                Assert-MockCalled Get-JujuCharmConfig -Exactly 1 -ParameterFilter {
                    $Scope -eq "change-hostname"
                }
            }

            It "Should call Rename-Computer one time" {
                Assert-MockCalled Rename-Computer -Exactly 1
            }

            It "Should call Set-CharmState one time" {
                Assert-MockCalled Set-CharmState -Exactly 1 -ParameterFilter {
                    ($Namespace -eq "Common") -and
                    ($Key -eq "HostnameChanged") -and
                    ($Value -eq $true)
                }
            }

            It "Should call Invoke-JujuReboot one time" {
                Assert-MockCalled Invoke-JujuReboot -Exactly 1 -ParameterFilter {
                    $Now -eq $true
                }
            }

            It "Should call Install-FreeRdp one time" {
                Assert-MockCalled Install-FreeRdp -Exactly 1
            }

            It "Should call Get-CharmServices one time" {
                Assert-MockCalled Get-CharmServices -Exactly 1
            }

            It "Should call Get-ManagementObject one time" {
                Assert-MockCalled Get-ManagementObject -Exactly 1
            }

            It "Should call Write-JujuWarning one time" {
                Assert-MockCalled Write-JujuWarning -Exactly 1 -ParameterFilter {
                    $Message -eq ("Changing computername from {0} to {1}" -f @($COMPUTERNAME, "whatever"))
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }

        Context "Is Nano and change hostname is false" {

            $object = New-Object -TypeName PSObject
            $method = {}
            Add-Member -InputObject $object -MemberType ScriptMethod `
                       -Name delete -Value $method

            Mock Get-IsNanoServer { return $true } -Verifiable
            Mock Write-JujuWarning {} -Verifiable
            Mock Set-PowerProfile {} -Verifiable
            Mock Start-TimeResync {} -Verifiable
            Mock Convert-JujuUnitNameToNetbios { return "whatever" } -Verifiable
            Mock Get-CharmState { return $false } -Verifiable
            Mock Get-JujuCharmConfig { return $false } -Verifiable
            Mock Install-FreeRdp {} -Verifiable
            Mock Get-CharmServices { return @{"free-rdp" = @{"service" = "whatever"}} } -Verifiable
            Mock Get-ManagementObject { return $object } -Verifiable
            Mock Stop-Service {} -Verifiable

            Start-InstallHook

            It "Should call Convert-JujuUnitNameToNetbios one time" {
                Assert-MockCalled Convert-JujuUnitNameToNetbios -Exactly 1
            }

            It "Should call Start-TimeResync one time" {
                Assert-MockCalled Start-TimeResync -Exactly 1
            }

            It "Should call Get-CharmState one time" {
                Assert-MockCalled Get-CharmState -Exactly 1 -ParameterFilter {
                    ($Namespace -eq "Common") -and
                    ($Key -eq "HostnameChanged")
                }
            }

            It "Should call Install-FreeRdp one time" {
                Assert-MockCalled Install-FreeRdp -Exactly 1
            }

            It "Should call Stop-Service one time" {
                Assert-MockCalled Stop-Service -Exactly 1
            }

            It "Should call Write-JujuWarning one time" {
                Assert-MockCalled Write-JujuWarning -Exactly 1 -ParameterFilter {
                    $Message -eq "Stop the service and then delete it"
                }
            }

            It "Should call Get-CharmServices one time" {
                Assert-MockCalled Get-CharmServices -Exactly 1
            }

            It "Should call Get-ManagementObject one time" {
                Assert-MockCalled Get-ManagementObject -Exactly 1
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Install-FreeRdp" {
        Context "Install from zip" {
            Mock Get-FreeRdpInstaller { return "whatever.zip" } -Verifiable
            Mock Install-FreeRdpFromZip { return $false} -Verifiable
            Mock Remove-Item {} -Verifiable

            Install-FreeRdp

            It "Should call Install-FreeRdpFromZip one time" {
                Assert-MockCalled Install-FreeRdpFromZip -Exactly 1 -ParameterFilter {
                    $InstallerPath -eq "whatever.zip"
                }
            }

            It "Should call Remove-Item one time" {
                Assert-MockCalled Remove-Item -Exactly 1
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }

        Context "Install from msi" {
            Mock Get-FreeRdpInstaller { return "whatever.msi" } -Verifiable
            Mock Install-FreeRdpFromMSI { return $false} -Verifiable
            Mock Remove-Item {} -Verifiable

            Install-FreeRdp

            It "Should call Install-FreeRdpFromMSI one time" {
                Assert-MockCalled Install-FreeRdpFromMSI -Exactly 1 -ParameterFilter {
                    $InstallerPath -eq "whatever.msi"
                }
            }

            It "Should call Remove-Item one time" {
                Assert-MockCalled Remove-Item -Exactly 1
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }

        Context "Installer should throw" {
            Mock Get-FreeRdpInstaller { return "whatever.bla" } -Verifiable

            It "Should throw" {
                { Install-FreeRdp } | Should throw "ERROR: Unknown installer extension: bla"
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Install-FreeRdpFromMSI" {
        Context "Process exited successfully" {
            Mock Write-JujuWarning {} -Verifiable
            Mock Test-Path { return $true } -Verifiable
            Mock Start-Process { return @{"ExitCode" = 0} } -Verifiable

            Install-FreeRdpFromMSI -InstallerPath "whatever.msi"

            It "Should call Start-Process one time" {
                Assert-MockCalled Start-Process -Exactly 1
            }

            It "Should call Write-JujuWarning three times" {
                Assert-MockCalled Write-JujuWarning -Exactly 3 -ParameterFilter {
                    ($Message -eq "Running FreeRdp installer from msi") -or
                    ($Message -eq "Installing from whatever.msi") -or
                    ($Message -eq "FreeRdp was installed from msi")
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }

        Context "Process exited with error" {
            Mock Write-JujuWarning {} -Verifiable
            Mock Test-Path { return $true } -Verifiable
            Mock Start-Process { return @{"ExitCode" = 30} } -Verifiable

            It "Should throw" {
                { Install-FreeRdpFromMSI -InstallerPath "whatever.msi" } | Should throw "Failed to install FreeRdp: 30"
            }
            It "Should call Start-Process one time" {
                Assert-MockCalled Start-Process -Exactly 1
            }

            It "Should call Write-JujuWarning two times" {
                Assert-MockCalled Write-JujuWarning -Exactly 2 -ParameterFilter {
                    ($Message -eq "Running FreeRdp installer from msi") -or
                    ($Message -eq "Installing from whatever.msi")
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Install-FreeRdpFromZIP" {
        Context "It was already installed" {
            Mock Write-JujuWarning {} -Verifiable
            Mock Test-Path { return $true } -Verifiable
            Mock Remove-Item {} -Verifiable
            Mock Expand-ZipArchive {} -Verifiable
            Mock Join-Path { return "what" } -Verifiable
            Mock Add-ToSystemPath {} -Verifiable

            Install-FreeRdpFromZip -InstallerPath "whatever.zip"

            It "Should call Test-Path two times" {
                Assert-MockCalled Test-Path -Exactly 2
            }

            It "Should call Remove-Item one time" {
                Assert-MockCalled Remove-Item -Exactly 1
            }

            It "Should call Expand-ZipArchive one time" {
                Assert-MockCalled Expand-ZipArchive -Exactly 1
            }

            It "Should call Join-Path one time" {
                Assert-MockCalled Join-Path -Exactly 1
            }

            It "Should call Add-ToSystemPath one time" {
                Assert-MockCalled Add-ToSystemPath -Exactly 1
            }

            It "Should call Write-JujuWarning one time" {
                Assert-MockCalled Write-JujuWarning -Exactly 2 -ParameterFilter {
                    ($Message -eq "Running FreeRdp installer from zip") -or
                    ($Message -eq ("Unzipping {0} to {1}" -f @("whatever.zip", $INSTALL_DIR)))
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }

        Context "It was not installed" {
            Mock Write-JujuWarning {} -Verifiable
            Mock Test-Path { return $false } -Verifiable
            Mock New-Item {} -Verifiable
            Mock Expand-ZipArchive {} -Verifiable
            Mock Join-Path { return "what" } -Verifiable
            Mock Add-ToSystemPath {} -Verifiable

            Install-FreeRdpFromZip -InstallerPath "whatever.zip"

            It "Should call Test-Path two times" {
                Assert-MockCalled Test-Path -Exactly 2
            }

            It "Should call New-Item one time" {
                Assert-MockCalled New-Item -Exactly 1
            }

            It "Should call Expand-ZipArchive one time" {
                Assert-MockCalled Expand-ZipArchive -Exactly 1
            }

            It "Should call Join-Path one time" {
                Assert-MockCalled Join-Path -Exactly 1
            }

            It "Should call Add-ToSystemPath one time" {
                Assert-MockCalled Add-ToSystemPath -Exactly 1
            }

            It "Should call Write-JujuWarning one time" {
                Assert-MockCalled Write-JujuWarning -Exactly 2 -ParameterFilter {
                    ($Message -eq "Running FreeRdp installer from zip") -or
                    ($Message -eq ("Unzipping {0} to {1}" -f @("whatever.zip", $INSTALL_DIR)))
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Start-ConfigChangedHook" {
        Context "When called" {
            Mock Write-JujuInfo {} -Verifiable
            Mock Write-JujuWarning {} -Verifiable
            Mock Test-Path { return $false } -Verifiable
            Mock New-FreeRDPConfigFile { return $true } -Verifiable
            Mock New-SelfSignedX509Cert {} -Verifiable
            Mock Get-CharmServices { 
                return @{"free-rdp" = @{
                    "service" = "whatever";
                    "config" = "whatever";
                }
            } } -Verifiable
            Mock Get-ManagementObject { return $false } -Verifiable
            Mock Join-Path { return "bla" } -Verifiable
            Mock New-Service {} -Verifiable
            Mock Start-Service {} -Verifiable
            Mock Get-JujuCharmConfig { return "whatever"} -Verifiable
            Mock Open-Ports {} -Verifiable
            Mock Set-JujuStatus {} -Verifiable

            Start-ConfigChangedHook

            It "Should call New-FreeRDPConfigFile one time" {
                Assert-MockCalled New-FreeRDPConfigFile -Exactly 1
            }

            It "Should call New-SelfSignedX509Cert one time" {
                Assert-MockCalled New-SelfSignedX509Cert -Exactly 1
            }

            It "Should call Join-Path two times" {
                Assert-MockCalled Join-Path -Exactly 2
            }

            It "Should call New-Service one time" {
                Assert-MockCalled New-Service -Exactly 1
            }

            It "Should call Start-Service one time" {
                Assert-MockCalled Start-Service -Exactly 1
            }

            It "Should call Open-Ports one time" {
                Assert-MockCalled Open-Ports -Exactly 1
            }

            It "Should call Write-JujuWarning three times" {
                Assert-MockCalled Write-JujuWarning -Exactly 3 -ParameterFilter {
                    ($Message -eq "Creating service whatever") -or
                    ($Message -eq "Open firewall on http and https ports") -or
                    ($Message -eq "Everything was good and config was generated")
                }
            }

            It "Should call Write-JujuInfo two times" {
                Assert-MockCalled Write-JujuInfo -Exactly 2 -ParameterFilter {
                    ($Message -eq "Start Config Changed Hook") -or
                    ($Message -eq "Finished Config Changed Hook")
                }
            }

            It "Should call Get-JujuCharmConfig two times" {
                Assert-MockCalled Get-JujuCharmConfig -Exactly 2 -ParameterFilter {
                    ($Scope -eq "http-port") -or
                    ($Scope -eq "https-port")
                }
            }

            It "Should call Set-JujuStatus one time" {
                Assert-MockCalled Set-JujuStatus -Exactly 1 -ParameterFilter {
                    ($Status -eq "active") -and
                    ($Message -eq "Unit is ready")
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }
    }

    Describe "Stop-Hook" {
        Context "Install from msi should throw" {
            Mock Write-JujuInfo {} -Verifiable
            Mock Get-FreeRdpInstaller { return "whatever.msi" } -Verifiable
            Mock Start-Process { return @{"ExitCode" = 30} } -Verifiable

            It "Should throw an error" {
                { Stop-Hook } | Should Throw "Failed to uninstall FreeRdp: 30"
            }

            It "Should call Start-Process one time" {
                Assert-MockCalled Start-Process -Exactly 1
            }

            It "Should call Write-JujuInfo one time" {
                Assert-MockCalled Write-JujuInfo -Exactly 1 -ParameterFilter {
                    $Message -eq "Start stop Hook"
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }

        Context "Install from msi should not throw" {
            $object = New-Object -TypeName PSObject
            $method = {}
            Add-Member -InputObject $object -MemberType ScriptMethod `
                       -Name delete -Value $method

            Mock Write-JujuInfo {} -Verifiable
            Mock Get-FreeRdpInstaller { return "whatever.msi" } -Verifiable
            Mock Start-Process { return @{"ExitCode" = 0} } -Verifiable
            Mock Remove-Item {} -Verifiable
            Mock Get-CharmServices { 
                return @{"free-rdp" = @{
                    "service" = "whatever";
                } } } -Verifiable
            Mock Write-JujuWarning {} -Verifiable
            Mock Test-Path { return $true } -Verifiable
            Mock Stop-Service {} -Verifiable
            Mock Get-ManagementObject { return $object } -Verifiable

            Stop-Hook

            It "Should call Start-Process one time" {
                Assert-MockCalled Start-Process -Exactly 1
            }

            It "Should call Remove-Item two times" {
                Assert-MockCalled Remove-Item -Exactly 2
            }

            It "Should call Get-CharmServices one time" {
                Assert-MockCalled Get-CharmServices -Exactly 1
            }

            It "Should call Get-ManagementObject one time" {
                Assert-MockCalled Get-ManagementObject -Exactly 1
            }

            It "Should call Stop-Service one time" {
                Assert-MockCalled Stop-Service -Exactly 1
            }

            It "Should call Test-Path one time" {
                Assert-MockCalled Test-Path -Exactly 1
            }

            It "Should call Test-Path one time" {
                Assert-MockCalled Test-Path -Exactly 1
            }

            It "Should call Write-JujuWarning two times" {
                Assert-MockCalled Write-JujuWarning -Exactly 2 -ParameterFilter {
                    ($Message -eq "Stop the service and then delete it") -or
                    ($Message -eq "Remove service folders")
                }
            }

            It "Should call Write-JujuInfo two times" {
                Assert-MockCalled Write-JujuInfo -Exactly 2 -ParameterFilter {
                    ($Message -eq "Start stop Hook") -or
                    ($Message -eq "Finished stop Hook")
                }
            }

            It "Should verify all mocks were called" {
                Assert-VerifiableMocks
            }
        }
    }
}