function Set-ADAuditingGroupAcl {
    <#
    .SYNOPSIS
        Sets an ACE on all objects in the Active Directory forest to allow a specified group to read all properties.

    .PARAMETER Group
        The group that will be given read access to all objects in the domain.
        Must be in NTAccount format (example: CONTOSO\Domain Admins).

    .PARAMETER Path
        The path to output JSON files that contain lists of objects that could not be updated, were updated, etc.
        If not specified, the current directory is used.

    .EXAMPLE
        Set-ADAuditingGroupAcl -Group 'CONTOSO\ADAuditingGroup'

        This example will add an ACE to all objects in the domain to allow the ADAuditingGroup group read access and
        output JSON files to the current directory.

    .EXAMPLE
        Set-ADAuditingGroupAcl -Group 'CONTOSO\ADAuditingGroup' -Path C:\ADAG\

        This example will add an ACE to all objects in the domain to allow the ADAuditingGroup group read access and
        output JSON files to C:\ADAG\.

    .INPUTS
        None

    .OUTPUTS
        ObjectsThatCouldNotBeUpdated.json
        ObjectsWithExistingAce.json
        ObjectsWithNewAce.json
        ObjectsWithUnreadableAcl.json
        ObjectsWithUnreadableSD.json
    #>
    [CmdLetBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Group,
        $Path = $PWD
    )

    #requires -Version 5

    # Clear old PSDrive
    if (Get-PSDrive ADDOMAIN -ErrorAction SilentlyContinue) { Remove-PSDrive ADDOMAIN }

    # Create ACE for reading the object
    $ReadProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
    $GenericExecute = [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute
    $Rights = $ReadProperty + $GenericExecute
    $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    $All = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $NTAccount = [System.Security.Principal.NTAccount]::New($Group)
    $AceToAdd = [System.DirectoryServices.ActiveDirectoryAccessRule]::New($NTAccount, $Rights, $Allow, $All)

    # Get all Domains in the forest
    $Domains = (Get-ADForest).Domains

    # Create empty objects to hold collected objects
    $ObjectsThatCouldNotBeUpdated = @()
    $ObjectsWithExistingAce = @()
    $ObjectsWithNewAce = @()
    $ObjectsWithUnreadableAcl = @()
    $ObjectsWithUnreadableSD = @()
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
                $ObjectsWithUnreadableSD += $object.DistinguishedName.ToString()
            }

            # Attempt to read ACE
            if ('' -eq $Acl.Access -or $null -eq $Acl.Access) {
                Write-Warning "Unable to read ACL from $($object.DistinguishedName)"
                $ObjectsWithUnreadableACL += $object.DistinguishedName.ToString()
            } else {
                # Check if desired ACE already exists
                $AceExists = $false
                foreach ($ace in $Acl.Access) {
                    if ($Ace.IdentityReference -eq $group -and
                        $Ace.ObjectType -eq '00000000-0000-0000-0000-000000000000' -and
                        $Ace.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000' -and
                        $Ace.ActiveDirectoryRights -match 'ReadProperty, GenericExecute') {
                        $AceExists = $true
                    }
                }

                if ($AceExists) {
                    Write-Verbose "Expected ACE already exists on $($object.DistinguishedName)"
                    $ObjectsWithExistingAce += $object.DistinguishedName.ToString()
                } else {
                    Write-Host "No ACE for $Group exists on $($object.DistinguishedName). Attempting to add the correct ACE."
                    $Acl.AddAccessRule($AceToAdd)

                    # Write the updated ACL on the Object
                    try {
                        Set-Acl -Path $ObjectPath -AclObject $Acl -ErrorAction Stop
                        
                    Write-Verbose "Successfully added ACE to $($object.DistinguishedName)"
                        $ObjectsWithNewAce += $object.DistinguishedName.ToString()
                    } catch {
                        Write-Warning "Could not grant $Group $Rights on $($object.DistinguishedName)"
                        $ObjectsThatCouldNotBeUpdated += $object.DistinguishedName.ToString()
                    }
                }
            }
            $ObjectCounter++
        }

        Remove-PSDrive ADDOMAIN
        $DomainCounter++
    }

    $ObjectsThatCouldNotBeUpdated | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsThatCouldNotBeUpdated.json') -Force
    $ObjectsWithExistingAce | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithExistingAce.json') -Force
    $ObjectsWithNewAce | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithNewAce.json') -Force
    $ObjectsWithUnreadableAcl | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithUnreadableAcl.json') -Force
    $ObjectsWithUnreadableSD | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithUnreadableSD.json') -Force
}