# CloudEndure

## Information
Currently, the cmdlets only support AWS environments being used as a migration target. Additional cloud environments as well as DR account support will be added as requested/needed.

## Usage

Import-Module CloudEndure

**Creates a new CloudEndure credential profile to use.**

    New-CEProfile -ProfileName "Lab" -Credential (New-Object -TypeName System.Management.Automation.PSCredential("john.smith@contoso.com", (ConvertTo-SecureString -String "My$ecureP@$$w0rd!" -AsPlainText -Force)))

**Gets a list of the existing profiles.**

    Get-CEProfile 

**Sets up a new persistent session to CloudEndure, you need to perform this before using any other cmdlets.
The passthru returns the key value the session information is stored with, it is the username/email used for the account.**

    $Email = New-CESession -ProfileName Lab -PassThru

**Alternatively, we could have specified a non-profile credential like this.**

    New-CESession -Credential (Get-Credential)

**Get license information.**

    Get-CELicense

**Gets the current blueprints.**

    Get-CEBlueprint

**Sets a new replication configuration, which will delete all existing replicated instances in the CloudEndure console.**

    New-CEReplicationConfiguration -Source 'Generic' -Target 'AWS US East (Northern Virginia)'

**Get info from multiple accounts, this assumes you have already performed a New-CESession for each of these email addresses.
The commands will get all of the blueprints in both accounts.**

    $Users = @("john.smith@contoso.com", "jane.smith@tailspintoys.com")

    foreach ($User in $Users)
	{
	    Get-CEBlueprint -Session $User
    }

**Removes all saved sessions. When you run New-CESession, whether you specify a credential or profile, there is an existing session.**

    Remove-CESession

## Revision History

### 1.1.0.0
Updated module for 100% API coverage including all target cloud environments, AWS, Azure, GCP, and Generic. This includes several additional cmdlets:

Get-CEMachineRecoveryPoints
Get-CEAccount
Set-CEProject
New-CECloudCredential
Get-CECloudCredential
Get-CECloud
Get-CESourceCloud
Get-CEMachineReplica
Invoke-CEMachineFailover
Invoke-CEReplicaCleanup

All of the List operations now support Offset and Limit parameters. You can also specify a non-default ProjectId or CloudCredential Id for each cmdlet that supports it.

The New-CEReplicationConfiguration cmdlet allows for the input of the SubnetId by both the long name (as presented in the CE console with VPC info) and as the normal subnet id.

This is really a BETA release, many of the cmdlets were refactored or updated with added validation or capabilities, but I may have typos or copy/paste errors I didn't catch through testing. 
Please report any bugs or errors, it's just me working on it.

** NOTE : Many of the CE APIs are case sensitive, you may receive an error response if one of the JSON keys in a POST, PATCH, or DELETE body is not capitalized correctly,
		use the -Verbose option to view additional details about the request to see if this may be an issue. Send me the details if you think this is the case.

### 1.0.0.3
Fixed typo in New-CEReplicationConfiguration.

### 1.0.0.2
Updated New-CESession cmdlet to reflect changes CloudEndure made to the API. Added Get-CEAccountSummary and Get-CESourceCloud cmdlets. Changed name of Get-CECloudRegions to Get-CECloudRegion and added an Id parameter.

### 1.0.0.1
Updated the Get-CEMachine cmdlet.

### 1.0.0.0
Initial Release.
