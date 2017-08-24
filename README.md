# CloudEndure

## Usage

Import-Module CloudEndure

\# Creates a new CloudEndure credential profile to use
New-CEProfile -ProfileName "Lab" -Credential (New-Object -TypeName System.Management.Automation.PSCredential("john.smith@contoso.com", (ConvertTo-SecureString -String "My$ecureP@$$w0rd!" -AsPlainText -Force)))

\# Gets a list of the existing profiles
Get-CEProfile 

\# Sets up a new persistent session to CloudEndure, you need to perform this before using any other cmdlets
\# The passthru returns the key value the session information is stored with, it is the username/email used for the account
$Email = New-CESession -ProfileName Lab -PassThru

\# Alternatively, we could have specified a non-profile credential like this
New-CESession -Credential (Get-Credential)

\# Get license information
Get-CELicenses

\# Gets the current blueprints
Get-CEBlueprint

\# Sets a new replication configuration, which will delete all existing replicated instances in the CloudEndure console
New-CEReplicationConfiguration -Source 'Generic' -Target 'AWS US East (Northern Virginia)'

\# Get info from multiple accounts, this assumes you have already performed a New-CESession for each of these email addresses
\# The commands will get all of the blueprints in both accounts
$Users = @("john.smith@contoso.com", "jane.smith@tailspintoys.com")

foreach ($User in $Users)
{
	Get-CEBlueprint -Session $User
}

\# Removes all saved sessions. When you run New-CESession, whether you specify a credential or profile, there is an existing session.
Remove-CESession

## Revision History

### 1.0.0.0
Initial Release.