function Remove-ADAuditingGroupAcl {
    <#
    .SYNOPSIS
        Removes an ACE from all objects in the Active Directory forest that allowed a specified group to read all properties.

    .PARAMETER Group
        The group that will have its read access on all objects in the domain removed.
        Must be in NTAccount format (example: CONTOSO\Domain Admins).

    .PARAMETER Path
        The path to output JSON files that contain lists of objects that could not be updated, were updated, etc.
        If not specified, the current directory is used.

    .EXAMPLE
        Remove-ADAuditingGroupAcl -Group 'CONTOSO\ADAuditingGroup'

        This example will remove the ADAuditingGroup's Read ACE from all objects in the forest and
        output JSON files to the current directory.

    .EXAMPLE
        Remove-ADAuditingGroupAcl -Group 'CONTOSO\ADAuditingGroup' -Path C:\ADAG\

        This example will remove the ADAuditingGroup's Read ACE from all objects in the forest and
        output JSON files to C:\ADAG\.

    .INPUTS
        None

    .OUTPUTS
        ObjectsThatCouldNotBeUpdatedRemove.json
        ObjectsWithAceAlreadyRemoved.json
        ObjectsWithAceRemoved.json
        ObjectsWithUnreadableACLRemove.json
        ObjectsWithUnreadableSDRemove.json
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
    $DomainCounter = 1
    foreach ($domain in $Domains) {
        Write-Host -Object "Updating ACLs on objects in $domain (Domain $DomainCounter of $($Domains.count) in the $((Get-ADForest).Name) forest.)" -ForegroundColor Blue -BackgroundColor Black

        # Get all objects in the domain (except excluded containers)
        $DomainADObjects = Get-ADObject -Filter * -Server $domain | Where-Object DistinguishedName -notmatch 'CN=Configuration,DC|CN=System,DC='

        # Create PSDrive for use in Get/Set-Acl
        New-PSDrive -Name ADDOMAIN -PSProvider ActiveDirectory -Server $domain -Scope Global -Root 'AD:' -ErrorAction Stop | Out-Null

        # Loop through all objects in the current domain
        $ObjectCounter = 1
        foreach ($object in $DomainADObjects) {
            Write-Progress -Activity "Attempting to update ACL on $($object.DistinguishedName)" -Status "$ObjectCounter/$($DomainADObjects.count)"

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
                $AceExists = $false
                foreach ($ace in $Acl.Access) {
                    if ($Ace.IdentityReference -eq $group -and
                        $Ace.ObjectType -eq '00000000-0000-0000-0000-000000000000' -and
                        $Ace.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000' -and
                        $Ace.ActiveDirectoryRights -match 'ReadProperty, GenericExecute') {
                        $AceExists = $true
                    }
                }

                if (-not $AceExists) {
                    Write-Verbose "ACE does not exist on $($object.DistinguishedName)"
                    $ObjectsWithAceAlreadyRemoved += $object.DistinguishedName.ToString()
                } else {
                    # Remove the ACE from ACL
                    $Acl.RemoveAccessRule($AceToRemove) | Out-Null

                    # Write the updated ACL on the Object
                    try {
                        Set-Acl -Path $ObjectPath -AclObject $Acl -ErrorAction Stop
                         Write-Verbose "Successfully removed ACE from $($object.DistinguishedName)"
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
