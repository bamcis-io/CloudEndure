# CloudEndure

*This project is no longer being maintained. AWS has acquired CloudEndure and it is now two native AWS services, [AWS Elastic Disaster Recovery](https://aws.amazon.com/disaster-recovery/) and [AWS Application Migration Service](https://aws.amazon.com/application-migration-service/), supported with their SDKs/CLI.*


I developed this module when working at a former job when we were using CloudEndure a lot to do migrations for a customer. That was in 2016/2017. I just rewrote this whole module, it is now an alpha release. Please test, submit issues, PRs, etc.

## Information
I have updated all cmdlets to target the latest version of the CE APIs, v5. Word of caution, their current API documentation [here](https://console.cloudendure.com/api_doc/apis.html) is terrible for a lot of their APIs. Some parameters are case sensitive when they shouldn't be, some APIs require the whole set of parameters in the json body, some accept just the ones with values, etc. It's a mess, but I tried my best to work around all of that.

## Usage

**Import the module**

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

### 2.0.0-alpha
The whole module has been almost completely rewritten. It now only targets the latest version of the API, v5. This is an alpha release, so certain components may not work, testing was only done against AWS.
	
### 1.2.1.0
Updated Get-CEWindowsInstaller so that the web response is returned to the pipeline.

Updated Start-CEDataReplication verbose message content.
		
Fixed Remove-CESession when a specific Session Id is provided so that the logout works.

### 1.2.0.3
Updated the Set-CEMachine cmdlet to comply with the launch time updates restriction. Converted the new version, v3, from the old names for that version, v14/v15 and translated the old version v12 to v2.

Added XSRF token support for v3 and later.

### 1.2.0.2
Fixed Remove-CEProfile.

### 1.2.0.1
Fixed bug in Invoke-CEMachineCutover adding the Ids to a collection.

### 1.2.0.0
Update the module to comply with the new version (v15) of the API. Added new cmdlets:

  Suspend-CEDataReplication
  Invoke-CELaunchTargetMachine
  Move-CEMachine
  Set-CEMachine
  Get-CEMachineBandwidth
  Set-CEMachineBandwidth

All cmdlets that are version specific will throw a runtime exception if the version the CE account is tied to is not supported by the cmdlet.

### 1.1.0.2
Removed the Get-CEAccountSummary cmdlet because it was using an undocumented API. Added the Get-CEAccountExtendedInfo cmdlet. Updated the error handling for all of the Invoke-WebRequest calls to make errors more accessible.

### 1.1.0.1
Fixed numerous bugs in the Blueprint cmdlets.

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
