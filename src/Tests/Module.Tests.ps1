[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'testing suite')] param()

Describe "Kari Module validity" {
    BeforeAll {
        $root = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath "../../src/Kari")
        $psm1Files = Get-ChildItem -Path $root -Recurse -Include '**/Kari.psm1' -File
        $psd1Files = Get-ChildItem -Path $root -Recurse -Include '**/Kari.psd1' -File
    }
    It "should validate manifest" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x | Should -Not -Be $null
            $x | Should -BeOfType [System.Management.Automation.PSModuleInfo]
        }
    }
    It "should explicitly psm1" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x.RootModule | Should -Not -BeNullOrEmpty
            $x.RootModule | Should -Match ".*\.psm1$"
        }
    }
    It "should contain a valid version" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x.Version | Should -Not -BeNullOrEmpty
            $x.Version | Should -Match "^\d+\.\d+\.\d+\.\d+$"
        }
    }
    It "should contain a valid GUID" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x.Guid | Should -Not -BeNullOrEmpty
            $x.Guid | Should -BeOfType [System.Guid]
            $x.Guid | Should -Not -Be [guid]::Empty
        }
    }
    It "should contain a valid author" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x.Author | Should -Not -BeNullOrEmpty
        }
    }
    It "should contain a valid description" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x.Description | Should -Not -BeNullOrEmpty
        }
    }
    It "should contain a valid company name" {
        $psd1Files | ForEach-Object {
            $x = Test-ModuleManifest -Path $_.FullName
            $x.CompanyName | Should -Not -BeNullOrEmpty
        }
    }
}
