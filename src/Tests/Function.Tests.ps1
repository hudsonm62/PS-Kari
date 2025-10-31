[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'testing suite')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'testing suite')]
param()

BeforeDiscovery {
    if(-not (Get-Module Kari -ErrorAction SilentlyContinue)){
        $KariRoot = Resolve-path (Join-Path -Path $PSScriptRoot -ChildPath "../Kari")
        Import-Module $KariRoot -Force -ErrorAction Stop
    }

    foreach ($module in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.SignIns')) {
        if(-not (Get-Module $module -ErrorAction SilentlyContinue)){
            Import-Module $module -Force -ErrorAction Stop
        }
    }
}

Describe "Assert-KariGraphConnection" {
    InModuleScope Kari {
        Context "validate true" {
            It "should be true with exact scopes" {
                Mock Get-MgContext { return @{ Scopes = @("Directory.Read.All") ;  TenantId = 'test' } }
                Assert-KariGraphConnection | Should -BeTrue
            }
            It "should be true with extra scopes" {
                Mock Get-MgContext { return @{ Scopes = @("Directory.Read.All", "some.other.scope", "and.one.more") ;  TenantId = 'test' } }
                Assert-KariGraphConnection | Should -BeTrue
            }
        }
        Context "validate false" {
            It "should be false with missing scope" {
                Mock Get-MgContext { return @{ Scopes = @("Application.Read.All") ;  TenantId = 'test' } }
                Assert-KariGraphConnection | Should -BeFalse
            }
        }
    }
}

Describe "Get-KariHuntAppResult" {
    # TODO - Criteria Ignore Tests
    Context "Criteria Tests" {
        BeforeAll {
            function Get-DummyApp {
                [OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal])]
                param (
                    [string]$DisplayName = "Some App",
                    [string]$AppId = [Guid]::NewGuid().ToString(),
                    [string]$Id = [Guid]::NewGuid().ToString(),
                    [datetime]$CreatedDateTime = (Get-Date),
                    [string[]]$RedirectUris = $null
                )
                $app = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal]::new()
                $app.DisplayName = $DisplayName
                $app.AppId = $AppId
                $app.Id = $Id
                $app.AdditionalProperties.createdDateTime = $CreatedDateTime
                $app.ReplyUrls = $RedirectUris

                return $app
            }
            function Get-DummyAppReg {
                [OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication])]
                param (
                    [string]$AppId = [Guid]::NewGuid().ToString(),
                    [string]$DisplayName = "Some App",
                    [Microsoft.Graph.PowerShell.Models.MicrosoftGraphPasswordCredential[]]$Secrets = @(),
                    [datetime]$CertEndDateTime = (Get-Date).AddYears(1),
                    [datetime]$SecretEndDateTime = (Get-Date).AddYears(1)
                )
                $appReg = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication]::new()
                $appReg.DisplayName = $DisplayName
                $appReg.AppId = $AppId
                $appReg.PasswordCredentials = $Secrets
                $appReg.CreatedDateTime = $CreatedDateTime
                $appReg.PublicClient.RedirectUris = $RedirectUris

                #dummy cert
                $DummyCert = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential]::new()
                $DummyCert.EndDateTime = $CertEndDateTime
                $appReg.KeyCredentials = @($DummyCert)

                #dummy client secret
                $DummySecret = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphPasswordCredential]::new()
                $DummySecret.EndDateTime = $SecretEndDateTime
                $DummySecret.DisplayName = "Dummy Secret"
                $appReg.PasswordCredentials = @($DummySecret)

                return $appReg
            }

            Mock Get-MgApplicationByAppId {
                Get-DummyAppReg
            } -ModuleName 'Kari'

            Mock Get-MgServicePrincipalOwnerAsUser {
                $DummyUser = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser]::new()
                $DummyUser.DisplayName = "Pester Identity"
                $DummyUser.Id = [Guid]::Empty.ToString()
                $DummyUser.UserPrincipalName = "pester.identity@contoso.com"
                return @($DummyUser)
            } -ModuleName 'Kari'

            Mock Get-KariSpPermissions {
                return @()
            } -ModuleName 'Kari'
        }

        It "should identify known rogue application" {
            # Select a random known app from the json list
            $RogueApps = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/huntresslabs/rogueapps/main/public/rogueapps.json' -Method Get

            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -AppId ($RogueApps | Get-Random).appId),
                $(Get-DummyApp -AppId ($RogueApps | Get-Random).appId),
                $(Get-DummyApp -AppId ($RogueApps | Get-Random).appId)
            )

            # results
            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 3
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Known Rogue Application"
            }
        }
        It "should identify generic display names" {
            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -DisplayName "Some Demo App"),
                $(Get-DummyApp -DisplayName "Some Cool - Trial"),
                $(Get-DummyApp -DisplayName "sample"),
                $(Get-DummyApp -DisplayName "testing only")
            )

            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 4
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Generic Application Name"
            }
        }
        It "should identify no alphanumeric characters in display names" {
            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -DisplayName "...."),
                $(Get-DummyApp -DisplayName "-@$%")
            )
            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 2
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "No Alphanumeric Characters"
            }
        }
        It "should identify loopback redirect URIs" {
            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -RedirectUris @('https://127.0.0.1:25/access', 'https://localhost:25/access')),
                $(Get-DummyApp -RedirectUris @('https://127.0.0.1', 'https://localhost')),
                $(Get-DummyApp -RedirectUris @('ms://127.0.0.1/', 'ms://localhost/'))
            )
            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 3
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Callback Redirect URI"
            }
        }
        It "should identify insecure HTTP redirect URIs" {
            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -RedirectUris @('http://someuri/access')),
                $(Get-DummyApp -RedirectUris @('http://someother:80/uri'))
            )
            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 2
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Insecure Redirect URI"
            }
        }
        It "should identify matching owner UPN to display name" {
            Mock Get-MgServicePrincipalOwnerAsUser {
                $DummyUser = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser]::new()
                $DummyUser.DisplayName = "Pester Identity"
                $DummyUser.Id = [Guid]::Empty.ToString()
                $DummyUser.UserPrincipalName = "pester@identity.com"
                return @($DummyUser)
            } -ModuleName 'Kari'

            $TestApp = Get-DummyApp -DisplayName "pester@identity.com"

            $results = Get-KariHuntAppResult -App $TestApp
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 1
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Display Name Matches Owner UPN"
            }
        }

        It "should identify short display names" {
            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -DisplayName "A"),
                $(Get-DummyApp -DisplayName "AB"),
                $(Get-DummyApp -DisplayName "x")
            )
            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 3
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Short Display Name"
            }
        }

        It "should identify expired certs" {
            Mock Get-MgApplicationByAppId {
                Get-DummyAppReg -AppId $args[0] -CertEndDateTime (Get-Date).AddDays(-1)
            } -ModuleName 'Kari'

            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp),
                $(Get-DummyApp)
            )

            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 2
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Expired Certificate"
            }
        }

        It "should identify expired secrets" {
            Mock Get-MgApplicationByAppId {
                Get-DummyAppReg -AppId $args[0] -SecretEndDateTime (Get-Date).AddDays(-1)
            } -ModuleName 'Kari'

            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp),
                $(Get-DummyApp)
            )

            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 2
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Expired Secret"
            }
        }

        It "should identify apps older than 3 years" {
            [Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]]$TestApps = @(
                $(Get-DummyApp -CreatedDateTime (Get-Date).AddYears(-4)),
                $(Get-DummyApp -CreatedDateTime (Get-Date).AddYears(-10)),
                $(Get-DummyApp -CreatedDateTime (Get-Date).AddYears(-3).AddDays(-1)),
                $(Get-DummyApp -CreatedDateTime (Get-Date).AddYears(-2))
            )
            $results = $TestApps | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 3
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "Old Application"
            }
        }

        It "should identify apps with risky API permissions" {
            # Mock the SpPermissions for now, this will be tested on its own
            Mock Get-KariSpPermissions {
                return @('Directory.AccessAsUser.All', 'Domain.ReadWrite.All', 'user.readwrite.all', 'gROUP.rEADWRITE.aLL', 'Some.Permission')
            } -ModuleName 'Kari'

            $TestApp = Get-DummyApp -DisplayName "Very Risky Application"
            $results = $TestApp | Get-KariHuntAppResult
            $results | Should -Not -BeNullOrEmpty
            $results | Should -HaveCount 4
            $results | ForEach-Object {
                $_.Issue | Should -BeExactly "High Risk API Permission"
            }
        }
    }
}
