@{
    AliasesToExport      = @()
    Author               = 'Jake Hildret'
    CmdletsToExport      = @()
    CompanyName          = 'Trimarc'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2024 - 2024 Jake Hildreth @ Trimarc. All rights reserved.'
    Description          = 'Simple project ADAuditingGroup'
    FunctionsToExport    = 'Get-AuditingGroupAcls.ps1'
    GUID                 = '92127ca3-34d8-46e9-b463-6f4023accbc4'
    ModuleVersion        = '1.0.0'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('ActiveDirectory', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility')
            Tags                       = @('Windows', 'MacOS', 'Linux')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility')
    RootModule           = 'ADAuditingGroup.psm1'
}