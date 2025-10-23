[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'psake')] param()
#region Props
FormatTaskName "-------- {0} --------"
Task default -Depends 'Lint'

properties {
    $root = $PSScriptRoot
    $ModuleSrc_Root = Join-Path $root "src"
    $DevScripts = Join-Path $root "scripts"

    $Module_Root = Join-Path $ModuleSrc_Root "Kari"

    # Pester Exclusions
    $ExcludeFiles = @(
        '*.Tests.ps1',
        '*.Mock.ps1',
        'psakefile.ps1',
        'bootstrap.ps1'
    )
    $ExcludeFolders = @(
        'node_modules',
        'src/Tests'
    )
    $ExcludeFoldersPattern = $ExcludeFolders -join '|'

    # Pester Config
    [PesterConfiguration]$PesterConfig = New-PesterConfiguration
    $PesterConfig.Run.Exit = $false
    $PesterConfig.TestResult.Enabled = $true
    $PesterConfig.TestResult.OutputFormat = 'NUnitXml'
    $PesterConfig.TestResult.OutputPath = Join-Path $root 'testResults.xml'
    $PesterConfig.TestDrive.Enabled = $false
    $PesterConfig.TestRegistry.Enabled = $false
}
#endregion

#region Pester
Task 'Test' {
    Invoke-Pester -Configuration $PesterConfig
}
Task 'Test-CI' -Description "CodeCoverage enabled tests" {
    $PesterConfigCI = $PesterConfig
    $PesterConfigCI.CodeCoverage.Enabled = $true
    $PesterConfigCI.CodeCoverage.Path = $ModuleSrc_Root # only for module source
    $PesterConfigCI.CodeCoverage.ExcludeTests = $true

    Invoke-Pester -Configuration $PesterConfigCI
}
Task 'Test-Diag' {
    $PesterConfigDiag = $PesterConfig
    $PesterConfigDiag.Debug.WriteDebugMessages = $true
    $PesterConfigDiag.Output.Verbosity = 'Diagnostic'

    Invoke-Pester -Configuration $PesterConfigDiag
}
#endregion

#region Lint
Task 'Lint' -Depends 'Prettier', 'Markdownlint', 'ScriptAnalyzer'
Task 'Prettier' {
    exec {
        npx prettier . --check
    }
}
Task 'Markdownlint' {
    exec {
        npx markdownlint-cli2 --config .markdownlint-cli2.jsonc
    }
}
Task 'ScriptAnalyzer' {
    Invoke-ScriptAnalyzer -Path $ModuleSrc_Root -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1')
} -Description 'Executes PSScriptAnalyzer'
#endregion

#region Lint-Write
Task 'Lint-Write' -Depends 'Prettier-Write'
Task 'Prettier-Write' {
    exec {
        npx prettier . --write
    }
}
#endregion

#region Misc
Task 'Clean' {
    # Clears temporary files
    $files = @(
        (Join-Path $root "node_modules")
        (Join-Path $root "package.json")
        (Join-Path $root "package-lock.json")
        (Join-Path $root "testResults.xml")
        (Join-Path $root "coverage.xml" )
    )

    foreach ($file in $files) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Get-ChildItem -Path $root -Filter "*.log" -File -Recurse | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    }
}
#endregion
