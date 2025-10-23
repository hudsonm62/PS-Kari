[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'testing suite')] param()

Describe "Text formatting" {
    BeforeAll {
        $root = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath "../../")
        $files = Get-ChildItem -Path $root -Recurse -Include '*.ps1','*.psm1','*.psd1','*.ps1xml','*.psrc' -File
    }

    It "should not contain tab characters in any PS files" {
        $files | ForEach-Object {
            $content = Get-Content -Path $_.FullName -Raw
            $content | Should -Not -Match "`t"
        }
    }

    It "should not contain Unicode characters" {
        $files | ForEach-Object {
            $content = Get-Content -Path $_.FullName -Raw
            $content | Should -Not -Match "[^\x00-\x7F]"
        }
    }
}
