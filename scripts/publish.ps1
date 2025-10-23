param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    $APIKey = $env:PSGALLERY_KEY
)

# validation
$Path = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath '../src/Kari') -ErrorAction Stop | Out-Null
$DataFile = Join-Path -Path $Path -ChildPath 'Kari.psd1'
$Manifest = Test-ModuleManifest -Path $DataFile -ErrorAction Stop

# publish
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$parameters = @{
    AllowPrerelease = $false
    Path            = $Path
    NuGetApiKey     = "$APIKey"
    Repository      = "PSGallery"
}
Publish-Module @parameters `
    -ErrorAction Stop -WarningAction Stop

Write-Information -InformationAction Continue -MessageData "$($Manifest.Name) $v published successfully to PSGallery!"

#Requires -Version 7
#Requires -Module PowerShellGet
