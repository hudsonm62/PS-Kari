[CmdletBinding(DefaultParameterSetName = 'Task')]
param(
    # Build task(s) to execute
    [parameter(ParameterSetName = 'task', position = 0)]
    [ArgumentCompleter( {
        param($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
        $psakeFile = Get-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath '../psakefile.ps1')
        switch ($Parameter) {
            'Task' {
                if ([string]::IsNullOrEmpty($WordToComplete)) {
                    Get-PSakeScriptTasks -buildFile $psakeFile | Select-Object -ExpandProperty Name | Sort-Object
                }
                else {
                    Get-PSakeScriptTasks -buildFile $psakeFile | Where-Object { $_.Name -like "$WordToComplete*" } | Select-Object -ExpandProperty Name | Sort-Object
                }
            }
            Default {}
        }
    })]
    [string[]]$Task = ''
)

$ProgPref = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

try {
    $x = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath "../requirements.psd1")
    Get-PackageProvider -Name Nuget -ForceBootstrap | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    if ((Test-Path -Path $x)) {
        if (-not (Get-Module -Name PSDepend -ListAvailable)) {
            Install-Module -Name PSDepend -Repository PSGallery -Scope CurrentUser
            Write-Debug "Missing PSDepend module installed."
        }
        if(-not (Get-Module -Name PSDepend)) { Import-Module -Name PSDepend }
        Invoke-PSDepend -Path $x -Install -Import -Force -WarningAction SilentlyContinue -ErrorAction Stop
        Write-Debug "Bootstrap completed successfully."
    } else {
        Write-Warning "No valid dependencies in '$x' can be found -- Skipping dependency installation."
    }
}
catch {
    throw "Failed to bootstrap..`n$_"
    $ProgressPreference = $ProgPref
}

if(-not [string]::IsNullOrEmpty($Task)){
    Invoke-psake -buildFile $psakeFile -taskList $Task -NoLogo
    $ProgressPreference = $ProgPref
    exit ([int](-not $psake.build_success))
} else {
    $ProgressPreference = $ProgPref
}

