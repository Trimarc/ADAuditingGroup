function New-ADAuditingGroup {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER Parameter

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .LINK
    #>
    [CmdletBinding()]
    param (
        $Forest = (Get-ADForest),
        $Domain = (Get-ADDomain -Server ( (Get-ADForest).RootDomain) ),
        $GroupName = 'ADAuditingGroup'
    )

    #requires -Version 5

    
        Write-Host @"
The following group is about to be created:

    Name:   $GroupName
    Domain: $($Domain.NetBIOSName)

"@  
    while ($Answer -ne 'y' -and $Answer -ne 'n') { 
        Write-Host 'Proceed? [y/n] ' -NoNewline
        $Answer = Read-Host
    }

    if ($Answer -eq 'y') {
        try {
            New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupScope Global -GroupCategory Security
            Write-Host "$GroupName was created successfully in the $Domain domain." -ForegroundColor Green
            $NewGroup = Get-ADGroup -Identity $GroupName -Server $Domain.DNSRoot -Properties *
            $NewGroup | Add-Member -NotePropertyName Domain -NotePropertyValue $Domain.DNSRoot -Force
            return $NewGroup
        } catch {
            throw $_
        }
    } else {
        Write-Host 'Goodbye!'
    }
}
