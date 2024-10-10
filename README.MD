# ADAuditingGroup

A collection of cmdlets to help create an Active Directory auditing group that can see into all the nooks and crannies of your forest.

- `New-ADAuditingGroup` - Creates a global group in the root domain and names it ADAuditingGroup.
- `New-ADAuditingGroupMember` - Creates a user or users with an '-audit' suffix and adds them to the newly created group.
- `Set-ADAuditingGroupAcl` - Creates an ACE that grants `ReadProperty, GenericExecute` on all attributes of an object to a specific group then adds that ACE to all objects in the forest (except the `System` and `Configuration` containers).
- `Remove-ADAuditingGroupAcl` - Removes any ACE that grants a specified group `ReadProperty, GenericExecute` on all attributes of an object.
