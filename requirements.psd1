@{
    'PSDependOptions'   = @{
        Target = 'CurrentUser'
    }

    'Pester'             = @{
        Version          = '5.7.1'
        Parameters       = @{
            SkipPublisherCheck = $true
        }
    }
    'psake'              = @{
        Version          = '4.9.1'
    }
    'PSScriptAnalyzer'   = @{
        Version          = '1.24.0'
    }

    # Graph Modules
    'Microsoft.Graph.Applications'   = @{
        Version         = '2.32.0'
    }
    'Microsoft.Graph.Authentication' = @{
        Version         = '2.32.0'
    }
    'Microsoft.Graph.Identity.SignIns' = @{
        Version         = '2.32.0'
    }

    # node dev deps
    'prettier'           = @{
        DependencyType   = 'Npm'
        Version          = '3.6.2'
        Target           = '.'
    }
    'markdownlint-cli2'  = @{
        DependencyType   = 'Npm'
        Version          = '0.19.1'
        Target           = '.'
    }
}
