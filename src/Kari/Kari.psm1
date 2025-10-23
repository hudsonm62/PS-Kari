#region Private Functions
function Assert-KariGraphConnection {
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Verbose "Not connected to Microsoft Graph"
        return $false
    }

    $ReqScopes = @("Application.Read.All", "User.Read.All")
    if(($ReqScopes | Where-Object { $context.Scopes -notcontains $_ }).Count -ne 0){
        Write-Verbose "Insufficient Graph API permissions. 'Application.Read.All' and 'User.Read.All' scope is least required."
        return $false
    }

    Write-Verbose "Connected to Tenant ID '$($context.TenantId)' with sufficient permissions."
    return $true
}

function Get-KnownRogueApplications {
    [CmdletBinding()]
    # https://huntresslabs.github.io/rogueapps/
    $JsonUri = 'https://raw.githubusercontent.com/huntresslabs/rogueapps/main/public/rogueapps.json'
    return Invoke-RestMethod -Uri $JsonUri -Method Get
}
#endregion


#region Public Functions

<#
.SYNOPSIS
    Analyzes a Microsoft Graph Application object for suspicious indicators.

.PARAMETER App
    The Microsoft Graph Application object to analyze. Supports multiple objects via pipeline input.

.PARAMETER IgnoreCriteria
    An array of criteria to ignore during analysis. Possible values: 'KnownRogueApps', 'GenericName', 'NoAlphanumeric', 'CallbackURI', 'InsecureURI', 'DisplayNameMatchesOwnerUPN', 'ShortDisplayName', 'ExpiredCertificate', 'ExpiredSecret', 'OldApplication'.

.EXAMPLE
    $SomeAppObject | Get-KariHuntAppResult

    Scans a single application object for suspicious indicators.

.EXAMPLE
    Get-MgApplication -All | Get-KariHuntAppResult

    Analyzes all applications in the tenant for suspicious indicators. Effectively the same as Invoke-KariHunt with less pre-checking.
#>
function Get-KariHuntAppResult {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication]$App,

        [Parameter(Mandatory = $false)][ValidateSet('KnownRogueApps', 'GenericName', 'NoAlphanumeric', 'CallbackURI', 'InsecureURI', 'DisplayNameMatchesOwnerUPN', 'ShortDisplayName', 'ExpiredCertificate', 'ExpiredSecret', 'OldApplication')]
        [string[]]$IgnoreCriteria = @()
    )

    begin {
        $results = New-Object System.Collections.ArrayList
        $KnownRogueApps = Get-KnownRogueApplications -ErrorAction Continue
        $Now = Get-Date
    }

    process {
        $RedirectUris = $App.PublicClient.RedirectUris
        Write-Verbose "Processing application: $($App.DisplayName)"

        # Check if application matches any known rogue applications
        if (@($IgnoreCriteria) -notcontains 'KnownRogueApps' -and ($KnownRogueApps | Where-Object { $App.AppId -eq $_.AppId })) {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "Known Rogue Application"
                Details = "This application is listed in the known rogue applications database."
            }) | Out-Null
            Write-Verbose "Rogue Application detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application display name similar to 'Test', 'Test app', etc.
        if (@($IgnoreCriteria) -notcontains 'GenericName' -and $App.DisplayName -match '(?i)(?:demo|test|testing|sample|example|placeholder|dummy|temp|trial)') {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "Generic Application Name"
                Details = "The application has a generic name which may indicate a test or placeholder application."
            }) | Out-Null
            Write-Verbose "Generic Application Name detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application name contains no alphanumeric characters
        if (@($IgnoreCriteria) -notcontains 'NoAlphanumeric' -and $App.DisplayName -notmatch '[a-zA-Z0-9]') {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "No Alphanumeric Characters"
                Details = "The application name contains no alphanumeric characters."
            }) | Out-Null
            Write-Verbose "No Alphanumeric Characters detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application reply URLs contain localhost or 127.0.0.1
        if (@($IgnoreCriteria) -notcontains 'CallbackURI' -and $RedirectUris -match 'localhost|127\.0\.0\.1') {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "Callback Redirect URI"
                Details = "The application contains a loopback redirect URI."
            }) | Out-Null
            Write-Verbose "Callback Redirect URI detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application reply URL is HTTP (not encrypted)
        if (@($IgnoreCriteria) -notcontains 'InsecureURI' -and $RedirectUris -match '^http://') {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "Insecure Redirect URI"
                Details = "The application contains an insecure HTTP redirect URI."
            }) | Out-Null
            Write-Verbose "Insecure Redirect URI detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application display name matches Owner(s) UPN
        if (@($IgnoreCriteria) -notcontains 'DisplayNameMatchesOwnerUPN') {
            foreach ($Owner in (Get-MgApplicationOwner -ApplicationId $App.AppId -ErrorAction SilentlyContinue)) {
                # faster to get one owner at a time, rather than get all users and filter later
                if ($App.DisplayName -eq (Get-MgUser -UserId $Owner.Id -ErrorAction SilentlyContinue).UserPrincipalName) {
                    $results.Add([PSCustomObject]@{
                        AppId = $App.AppId
                        DisplayName = $App.DisplayName
                        Issue = "Display Name Matches Owner UPN"
                        Details = "The application display name matches an owner's user principal name."
                    }) | Out-Null
                    Write-Verbose "Display Name Matches Owner UPN detected: $($App.DisplayName) ($($App.AppId))"
                }
            }
        }

        # Check if application display name is less than 3 characters
        if (@($IgnoreCriteria) -notcontains 'ShortDisplayName' -and $App.DisplayName.Length -lt 3) {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "Short Display Name"
                Details = "The application display name is less than 3 characters."
            }) | Out-Null
            Write-Verbose "Short Display Name detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if Application Certificates are expired
        if (@($IgnoreCriteria) -notcontains 'ExpiredCertificate') {
            foreach ($Cert in $App.KeyCredentials) {
                if ($Cert.EndDateTime -lt $Now) {
                    $results.Add([PSCustomObject]@{
                        AppId = $App.AppId
                        DisplayName = $App.DisplayName
                        Issue = "Expired Certificate"
                        Details = "The application has an expired certificate."
                    }) | Out-Null
                    Write-Verbose "Expired Certificate detected: $($App.DisplayName) ($($App.AppId))"
                }
            }
        }

        # Check if Secrets are expired
        if (@($IgnoreCriteria) -notcontains 'ExpiredSecret') {
            foreach ($Secret in $App.PasswordCredentials) {
                if ($Secret.EndDateTime -lt $Now) {
                    $results.Add([PSCustomObject]@{
                        AppId = $App.AppId
                        DisplayName = $App.DisplayName
                        Issue = "Expired Secret"
                        Details = "The application has an expired secret."
                    }) | Out-Null
                    Write-Verbose "Expired Secret detected: $($App.DisplayName) ($($App.AppId))"
                }
            }
        }

        # Check if App is older than 3 years
        if (@($IgnoreCriteria) -notcontains 'OldApplication' -and ($Now - $App.CreatedDateTime).TotalDays -gt 1095) {
            $results.Add([PSCustomObject]@{
                AppId = $App.AppId
                DisplayName = $App.DisplayName
                Issue = "Old Application"
                Details = "The application was created more than 3 years ago."
            }) | Out-Null
            Write-Verbose "Old Application detected: $($App.DisplayName) ($($App.AppId))"
        }
    }
    end {
        return $results
    }
}
Export-ModuleMember -Function Get-KariHuntAppResult

<#
.SYNOPSIS
    Hunts down any suspicious applications in the tenant.

.DESCRIPTION
    Hunts down any suspicious applications in the tenant by analyzing a set of properties against known indicators of compromise and best practices.

.PARAMETER IgnoreCriteria
    An array of criteria to ignore during analysis. Possible values: 'KnownRogueApps', 'GenericName', 'NoAlphanumeric', 'CallbackURI', 'InsecureURI', 'DisplayNameMatchesOwnerUPN', 'ShortDisplayName', 'ExpiredCertificate', 'ExpiredSecret', 'OldApplication'.

.EXAMPLE
    Invoke-KariHunt

    Checks all applications against the criteria and outputs as an ArrayList of objects.

.EXAMPLE
    Invoke-KariHunt | Export-Csv -Path './report.csv'

    Exports a CSV report of the results

.EXAMPLE
    Invoke-KariHunt -IgnoreCriteria 'OldApplication','ExpiredSecret'

    Ignores checking for applications that are old and applications with expired secrets.

.LINK
    https://github.com/hudsonm62/PS-Kari
#>
function Invoke-KariHunt {
    [CmdletBinding()][Alias('ikh')]
    param (
        [Parameter(Mandatory = $false)][ValidateSet('KnownRogueApps', 'GenericName', 'NoAlphanumeric', 'CallbackURI', 'InsecureURI', 'DisplayNameMatchesOwnerUPN', 'ShortDisplayName', 'ExpiredCertificate', 'ExpiredSecret', 'OldApplication')]
        [string[]]$IgnoreCriteria = @()
    )

    # Validate Graph connection
    if(-not (Assert-KariGraphConnection)) {
        throw "Not connected to Microsoft Graph with sufficient permissions. Please connect using Connect-MgGraph with 'Application.Read.All' and 'User.Read.All' scopes."
    }

    # Get All Applications
    $AllApps = Get-MgApplication -All -ErrorAction Stop
    Write-Verbose "Retrieved $($AllApps.Count) applications from Microsoft Graph."

    # Process Applications
    $result = $AllApps | Get-KariHuntAppResult -IgnoreCriteria $IgnoreCriteria

    if($result.Count -le 0){
        Write-Information "No suspicious applications found." -InformationAction Continue
        return $null
    } else {
        Write-Verbose "Found $($result.Count) suspicious applications."
        return $result
    }
}
Export-ModuleMember -Function Invoke-KariHunt -Alias 'ikh'

#endregion
