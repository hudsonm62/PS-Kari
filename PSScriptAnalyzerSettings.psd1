@{
    Rules = @{
        PSUseSingularNouns = @{
            Enable           = $false
        }
        PSAvoidUsingPositionalParameters = @{
            CommandAllowList = 'npx'
        }
    }
}
