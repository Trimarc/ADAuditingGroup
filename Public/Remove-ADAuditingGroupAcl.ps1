function Remove-ADAuditingGroupAcl {
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
        [Parameter(Mandatory)]
        $Group,
        $Path = $PWD
    )

    #requires -Version 5

    # Create ACE to remove the object
    $ReadProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
    $GenericExecute = [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute
    $Rights = $ReadProperty + $GenericExecute
    $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    $All = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $NTAccount = [System.Security.Principal.NTAccount]::New($Group)
    $AceToRemove = [System.DirectoryServices.ActiveDirectoryAccessRule]::New($NTAccount, $Rights, $Allow, $All)

    # Get all Domains in the forest
    $Domains = (Get-ADForest).Domains

    # Create empty objects to hold collected objects
    $ObjectsThatCouldNotBeUpdatedRemove = @()
    $ObjectsWithAceAlreadyRemoved = @()
    $ObjectsWithAceRemoved = @()
    $ObjectsWithUnreadableACLRemove = @()
    $ObjectsWithUnreadableSDRemove = @()
    $Acl = $null

    # Loop through all domains in the forest
    foreach ($domain in $Domains) {

        # Get all objects in the domain (except excluded containers)
        $DomainADObjects = Get-ADObject -Filter * -Server $domain | Where-Object DistinguishedName -notmatch 'CN=Configuration,DC|CN=System,DC='

        # Create PSDrive for use in Set-Acl
        New-PSDrive -Name ADDOMAIN -PSProvider ActiveDirectory -Server $domain -Scope Global -Root 'AD:' -ErrorAction Stop | Out-Null

        # Loop through all objects in the current domain
        foreach ($object in $DomainADObjects) {
            $ObjectPath = "ADDOMAIN:\$($object.DistinguishedName)"

            # Get the ACL for the Object
            try {
                $Acl = Get-Acl -Path $ObjectPath -ErrorAction Stop
            } catch {
                $Acl = ''
                Write-Warning "Cannot read Security Descriptor from $($object.DistinguishedName)"
                $ObjectsWithUnreadableSDRemove += $object.DistinguishedName.ToString()
            }

            # Attempt to read ACE
            if ('' -eq $Acl.Access -or $null -eq $Acl.Access) {
                Write-Warning "Unable to read ACL from $($object.DistinguishedName)"
                $ObjectsWithUnreadableACLRemove += $object.DistinguishedName.ToString()
            } else {
                # Check if ACE to be removed already exists

                if ($AceExists) {
                    $ObjectsWithAceAlreadyRemoved += $object.DistinguishedName.ToString()
                } else {
                    $AceExists = $false
                    foreach ($ace in $Acl.Access) {
                        if ($Ace.IdentityReference -eq $group -and
                            $Ace.ObjectType -eq '00000000-0000-0000-0000-000000000000' -and
                            $Ace.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000' -and
                            $Ace.ActiveDirectoryRights -match 'ReadProperty, GenericExecute') {
                            $AceExists = $true
                        }
                    }
                    # Remove the ACE from ACL
                    $Acl.RemoveAccessRule($AceToRemove) | Out-Null

                    # Write the updated ACL on the Object
                    try {
                        Set-Acl -Path $ObjectPath -AclObject $Acl -ErrorAction Stop
                        $ObjectsWithAceRemoved += $object.DistinguishedName.ToString()
                    } catch {
                        Write-Warning "Could not remove $Group $Rights from $($object.DistinguishedName)"
                        $ObjectsThatCouldNotBeUpdatedRemove += $object.DistinguishedName.ToString()
                    }
                }
                
            }
        }

        Remove-PSDrive ADDOMAIN
    }

    $ObjectsThatCouldNotBeUpdatedRemove | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsThatCouldNotBeUpdatedRemove.json') -Force
    $ObjectsWithAceAlreadyRemoved | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithAceAlreadyRemoved.json') -Force
    $ObjectsWithAceRemoved | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithAceRemoved.json') -Force
    $ObjectsWithUnreadableACLRemove | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithUnreadableACLRemove.json') -Force
    $ObjectsWithUnreadableSDRemove | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithUnreadableSDRemove.json') -Force
}
