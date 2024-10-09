function Set-ADAuditingGroupAcl {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER Parameter

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .LINK
    #>
    [CmdLetBinding()]
    param (
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
    foreach ($domain in $Domains) {

        # Get all objects in the domain (except excluded containers)
        $DomainADObjects = Get-ADObject -Filter * -Server $domain | Where-Object DistinguishedName -notmatch 'CN=Configuration,DC|CN=System,DC='

        # Create PSDrive for use in Get/Set-Acl
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
                    # Write-Host "$Group should be able to read $($object.DistinguishedName)"
                    $ObjectsWithExistingAce += $object.DistinguishedName.ToString()
                } else {
                    Write-Host "No ACE for $Group exists on $($object.DistinguishedName). Attempting to add the correct ACE."
                    $Acl.AddAccessRule($AceToAdd)

                    # Write the updated ACL on the Object
                    try {
                        Set-Acl -Path $ObjectPath -AclObject $Acl -ErrorAction Stop
                        $ObjectsWithNewAce += $object.DistinguishedName.ToString()
                    } catch {
                        Write-Warning "Could not grant $Group $Rights on $($object.DistinguishedName)"
                        $ObjectsThatCouldNotBeUpdated += $object.DistinguishedName.ToString()
                    }
                }
            }
        }

        Remove-PSDrive ADDOMAIN
    }

    $ObjectsThatCouldNotBeUpdated | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsThatCouldNotBeUpdated.json') -Force
    $ObjectsWithExistingAce | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithExistingAce.json') -Force
    $ObjectsWithNewAce | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithNewAce.json') -Force
    $ObjectsWithUnreadableAcl | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithUnreadableAcl.json') -Force
    $ObjectsWithUnreadableSD | ConvertTo-Json | Out-File -FilePath (Join-Path -Path $Path -ChildPath 'ObjectsWithUnreadableSD.json') -Force
}