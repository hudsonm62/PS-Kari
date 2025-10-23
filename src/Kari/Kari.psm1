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

function Get-KariHuntResultObject {
    [CmdletBinding()]
    param (
        [guid]$AppId, [guid]$ObjectId, [string]$DisplayName,
        [string]$Issue, [string]$Details,
        [datetime]$CreatedAt
    )

    return [PSCustomObject]@{
        AppId       = $AppId
        ObjectId    = $ObjectId
        DisplayName = $DisplayName
        Issue       = $Issue
        Details     = $Details
        CreatedAt   = $CreatedAt
    }
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

        $AppCommonMeta = @{
            AppId = $App.AppId
            ObjectId = $App.Id
            DisplayName = $App.DisplayName
            CreatedAt = $App.CreatedDateTime
        }

        # Check if application matches any known rogue applications
        if (@($IgnoreCriteria) -notcontains 'KnownRogueApps' -and ($KnownRogueApps | Where-Object { $App.AppId -eq $_.AppId })) {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "Known Rogue Application" -Details "App listed in a known rogue applications database - '$($App.DisplayName)'.")
            ) | Out-Null
            Write-Verbose "Rogue Application detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application display name similar to 'Test', 'Test app', etc.
        if (@($IgnoreCriteria) -notcontains 'GenericName' -and $App.DisplayName -match '(?i)(?:demo|test|testing|sample|example|placeholder|dummy|temp|trial)') {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "Generic Application Name" -Details "Generic/non-meaningful named app - '$($App.DisplayName)'.")
            ) | Out-Null
            Write-Verbose "Generic Application Name detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application name contains no alphanumeric characters
        if (@($IgnoreCriteria) -notcontains 'NoAlphanumeric' -and $App.DisplayName -notmatch '[a-zA-Z0-9]') {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "No Alphanumeric Characters" -Details "Name contains no alphanumeric characters - '$($App.DisplayName)'.")
            ) | Out-Null
            Write-Verbose "No Alphanumeric Characters detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application reply URLs contain localhost or 127.0.0.1
        $CallbackMatch = $RedirectUris -match 'localhost|127\.0\.0\.1'
        if (@($IgnoreCriteria) -notcontains 'CallbackURI' -and $CallbackMatch) {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "Callback Redirect URI" -Details "Contains a loopback redirect URI - '$($CallbackMatch -join ', ')'.")
            ) | Out-Null
            Write-Verbose "Callback Redirect URI detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application reply URL is HTTP (not encrypted)
        $RedirectMatch = $RedirectUris -match '^http://'
        if (@($IgnoreCriteria) -notcontains 'InsecureURI' -and $RedirectMatch) {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "Insecure Redirect URI" -Details "Contains insecure HTTP redirect URI - '$($RedirectMatch -join ', ')'.")
            ) | Out-Null
            Write-Verbose "Insecure Redirect URI detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if application display name matches Owner(s) UPN
        if (@($IgnoreCriteria) -notcontains 'DisplayNameMatchesOwnerUPN') {
            foreach ($Owner in (Get-MgApplicationOwner -ApplicationId $App.AppId -ErrorAction SilentlyContinue)) {
                # faster to get one owner at a time, rather than get all users and filter later
                if ($App.DisplayName -eq (Get-MgUser -UserId $Owner.Id -ErrorAction SilentlyContinue).UserPrincipalName) {
                    $results.Add(
                        $(Get-KariHuntResultObject @AppCommonMeta `
                            -Issue "Display Name Matches Owner UPN" -Details "Name matches an owner's UPN name - $($App.DisplayName).")
                    )
                    Write-Verbose "Display Name Matches Owner UPN detected: $($App.DisplayName) ($($App.AppId))"
                }
            }
        }

        # Check if application display name is less than 3 characters
        if (@($IgnoreCriteria) -notcontains 'ShortDisplayName' -and $App.DisplayName.Length -lt 3) {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "Short Display Name" -Details "Display name is less than 3 characters - '$($App.DisplayName)'.")
            ) | Out-Null
            Write-Verbose "Short Display Name detected: $($App.DisplayName) ($($App.AppId))"
        }

        # Check if Application Certificates are expired
        if (@($IgnoreCriteria) -notcontains 'ExpiredCertificate') {
            foreach ($Cert in $App.KeyCredentials) {
                if ($Cert.EndDateTime -lt $Now) {
                    $results.Add(
                        $(Get-KariHuntResultObject @AppCommonMeta `
                            -Issue "Expired Certificate" -Details "Has an expired certificate - '$($Cert.DisplayName)'.")
                    ) | Out-Null
                    Write-Verbose "Expired Certificate detected: $($App.DisplayName) ($($App.AppId))"
                }
            }
        }

        # Check if Secrets are expired
        if (@($IgnoreCriteria) -notcontains 'ExpiredSecret') {
            foreach ($Secret in $App.PasswordCredentials) {
                if ($Secret.EndDateTime -lt $Now) {
                    $results.Add(
                        $(Get-KariHuntResultObject @AppCommonMeta `
                            -Issue "Expired Secret" -Details "Has an expired secret - '$($Secret.DisplayName)'.")
                    ) | Out-Null
                    Write-Verbose "Expired Secret detected: $($App.DisplayName) ($($App.AppId))"
                }
            }
        }

        # Check if App is older than 3 years
        if (@($IgnoreCriteria) -notcontains 'OldApplication' -and ($Now - $App.CreatedDateTime).TotalDays -gt 1095) {
            $results.Add(
                $(Get-KariHuntResultObject @AppCommonMeta `
                    -Issue "Old Application" -Details "Created over 3 years ago - '$($App.CreatedDateTime.ToString('yyyy-MM-dd'))'.")
            ) | Out-Null
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
