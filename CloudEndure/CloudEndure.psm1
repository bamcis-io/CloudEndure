$script:URL = "https://console.cloudendure.com/api"
$script:Installer = "https://console.cloudendure.com/installer_win.exe"
$script:ProfileLocation = "$env:USERPROFILE\.cloudendure\credentials"
[System.Collections.Hashtable]$script:AWSRegionMap = @{
	"Generic" = "f54420d5-3de4-40bb-b35b-33d32ad8c8ef";
	"AWS US East (Northern Virginia)" = "47d842b8-ebfa-4695-90f8-fb9ab686c708";
	"AWS US West (Northern California)" = "959d856b-3730-48c2-84ba-a509497b2085";
	"AWS US West (Oregon)" = "31cc9e94-58af-4920-9cd7-db6a45f28fd4";
	"AWS EU (Ireland)" = "114b110d-00ad-48d4-a930-90cb3f8cde2e";
	"AWS EU (Frankfurt)" = "349db794-4bfc-4fc5-a733-659081d6729d";
	"AWS Asia Pacific (Singapore)" = "fc89da33-0eab-4602-8e4d-8c35b0ad8f65";
	"AWS Asia Pacific (Sydney)" = "4b4a4ff4-e5d9-4b62-8e7c-7210c9ea2be2";
	"AWS Asia Pacific (Tokyo)" = "acce3f71-3e7e-48db-bc5c-84d57f84f919";
	"AWS South America (Sao Paulo)" = "5dbb0a54-3361-4a6b-9dcb-1a1f87f4e1a2";
	"AWS US East (Ohio)" = "2941040c-a410-4bec-8842-566da8ca7729";
	"AWS Asia Pacific (Mumbai)" = "e5dfe786-736f-4f15-a737-7915e1a98349";
	"AWS Asia Pacific (Seoul)" = "1c805747-322d-4f04-b0cc-022a63baa824";
	"AWS EU (London)" = "0191fdf5-779f-4a54-a0ce-6e3b5157ce36";
	"AWS Canada (Central)" = "910a2cd6-0298-4c9b-82f5-74d6bd265211"
}
[System.Collections.Hashtable]$script:CloudIds = @{
	"AWS" = "4c7b3582-9e73-4866-858a-8e1ac6e818b3";
	"Generic" = "f54420d5-3de4-40bb-b35b-33d32ad8c8ef";
	"On-Premises" = "00000000-0000-0000-0000-000000000000"
}

[System.Collections.Hashtable]$script:Sessions = @{}

[System.String[]]$script:CommonParams = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters + @("PassThru", "Force", "Session", "ProjectId")
[System.String]$script:AllParameterSets = "__AllParameterSets"

#region Profiles & Sessions

Function New-CEProfile {
	<#
		.SYNOPSIS
			Saves a new CloudEndure profile.

		.DESCRIPTION
			The cmdlet saves a username and password (encrypted using the Windows DPAPI under the current user's context) to a file at a specified profile location.
			The profile credentials can be called later during the New-CESession cmdlet to simplify remembering credentials.

		.PARAMETER Credential
			The credentials to save.

		.PARAMTER ProfileName
			The name of the profile.

		.PARAMETER ProfileLocation
			Specify a non-default location to store the profile file. This defaults to $env:USERPROFILE\.cloudendure\credentials

		.EXAMPLE
			New-CEProfile -ProfileName "MyCEProfile" -Credential (New-Object -TypeName System.Management.Automation.PSCredential("john.smith@contoso.com", (ConvertTo-SecureString -String "My$ecurEP@$$w0Rd" -AsPlainText -Force))

			This saves a new profile named MyCEProfile with the specified credentials.

		.INPUTS
			System.Management.Automation.PSCredential
				
		.OUTPUTS
			None

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential,

		[Parameter(Mandatory = $true, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ProfileName,

		[Parameter(Position = 2)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		Write-Verbose -Message "Using profile location $ProfileLocation."

		if (-not (Test-Path -Path $ProfileLocation -PathType Leaf))
		{
			Write-Verbose -Message "Creating new credentials file at $ProfileLocation."
			New-Item -Path $ProfileLocation -ItemType File -Force
		}
		
		# This will store the password encrypted with the Windows DPAPI using the user's credentials
		$Profile = @{"username" = $Credential.UserName; "password" = ConvertFrom-SecureString -SecureString $Credential.Password}

		$Content = Get-Content -Path $ProfileLocation -Raw

		if ($Content -ne $null -and -not [System.String]::IsNullOrEmpty($Content))
		{
			[PSCustomObject]$Json = ConvertFrom-Json -InputObject $Content
		}
		else
		{
			[PSCustomObject]$Json = [PSCustomObject]@{}
		}

		if ((Get-Member -InputObject $Json -Name $ProfileName -MemberType Properties) -ne $null) 
		{
			Write-Warning -Message "The profile $ProfileName is being overwritten with new data."
			$Json.$ProfileName =  $Profile
		}
		else 
		{
			$Json | Add-Member -MemberType NoteProperty -Name $ProfileName -Value $Profile
		}

		Set-Content -Path $ProfileLocation -Value (ConvertTo-Json -InputObject $Json)
		Write-Verbose -Message "Successfully saved credentials."
	}

	End {
	}
}

Function Get-CEProfile {
	<#
		.SYNOPSIS
			Gets profile information.

		.DESCRIPTION
			This cmdlet retrieves a list of available profile names if no profile name is specified. If a profilename is specified, a PSCredential object is returned back if the profile is found.

		.PARAMETER ProfileName
			The name of the profile to retrieve. If this is not specified, a list of available profile names is returned.

		.PARAMETER ProfileLocation
			The location of the profile credential data. This defaults to $env:USERPROFILE\.cloudendure\credentials.

		.EXAMPLE
			Get-CEProfile
			
			This returns a list of available profiles.

		.EXAMPLE
			Get-CEProfile -ProfileName MyCEProfile

			This returns a PSCredential object with the credentials stored as MyCEProfile using the New-CEProfile cmdlet.

		.INPUTS
			System.String

		.OUTPUTS
			System.String[] or System.Management.Automation.PSCredential

			If no profile is specified, an array of profile names is returned. If the profile name is specified, the PSCredential object is returned.

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCredential], [System.String[]])]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ProfileName = [System.String]::Empty,

		[Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ProfileLocation = [System.String]::Empty
	)

	Begin {
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		if (Test-Path -Path $ProfileLocation -PathType Leaf)
		{
			$Content = Get-Content -Path $ProfileLocation -Raw

			if ($Content -ne $null -and -not [System.String]::IsNullOrEmpty($Content))
			{
				[PSCustomObject]$Json = ConvertFrom-Json -InputObject $Content
			}
			else
			{
				[PSCustomObject]$Json = [PSCustomObject]@{}
			}

			if (-not [System.String]::IsNullOrEmpty($ProfileName))
			{
				$Value = $Json | Get-Member -MemberType Properties -Name $ProfileName
				
				if ($Value -ne $null)
				{
					# Convert the stored data back to a PSCredential object
					Write-Output -InputObject (New-Object -TypeName System.Management.Automation.PSCredential($Json.$ProfileName.username, (ConvertTo-SecureString -String $Json.$ProfileName.password)))
				}
				else
				{
					Write-Warning -Message "No profile matching $ProfileName in $ProfileLocation"
				}
			}
			else 
			{
				# This will return all of the "keys" which are the profile names
				Write-Output -InputObject ($Json | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)
			}
		}
		else
		{
			Write-Warning -Message "No profile data stored at $ProfileLocation"
		}
	}

	End {
	}
}

Function Remove-CEProfile {
	<#
		.SYNOPSIS
			Removes a CE profile.

		.DESCRIPTION
			This cmdlet retrieves the specified profile and deletes it from the credentials file.

		.PARAMETER ProfileName
			The name of the profile to remove.

		.PARAMETER ProfileLocation
			The location of the profile credential data. This defaults to $env:USERPROFILE\.cloudendure\credentials.

		.PARAMETER PassThru
			If specified, the deleted profile is returned as a PSCredential object.

		.EXAMPLE
			Remove-CEProfile -ProfileName "MyCEProfile"

			Removes the MyCEProfile profile.

		.INPUTS
			System.String

		.OUTPUTS
			None or System.Management.Automation.PSCredential

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([System.Management.Automation.PSCredential])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ProfileName = [System.String]::Empty,

		[Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ProfileLocation = [System.String]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		if (Test-Path -Path $ProfileLocation -PathType Leaf)
		{
			$Content = Get-Content -Path $ProfileLocation -Raw

			if ($Content -ne $null -and -not [System.String]::IsNullOrEmpty($Content))
			{
				[PSCustomObject]$Json = ConvertFrom-Json -InputObject $Content
				$Value = $Json | Get-Member -MemberType Properties -Name $ProfileName
				
				if ($Value -ne $null)
				{
					# Convert the stored data back to a PSCredential object
					$Creds = New-Object -TypeName System.Management.Automation.PSCredential($Json.$ProfileName.username, (ConvertTo-SecureString -String $Json.$ProfileName.password))

					$ConfirmMessage = "You are about to delete profile $ProfileName."
					$WhatIfDescription = "Deleted profile $ProfileName"
					$ConfirmCaption = "Delete CE Profile"

					if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
					{
						Set-Content -Path $ProfileLocation -Value (ConvertTo-Json -InputObject ($Json | Select-Object -ExcludeProperty $ProfileName))

						if ($PassThru) 
						{
							Write-Output -InputObject $Creds
						}
					}
				}
				else
				{
					Write-Warning -Message "No profile matching $ProfileName in $ProfileLocation"
				}
			}
		}
		else
		{
			Write-Warning -Message "No profile data stored at $ProfileLocation"
		}
	}

	End {
	}
}

Function New-CESession {
    <#
        .SYNOPSIS
            Establishes a new session with the CE console

        .DESCRIPTION
            The cmdlet establishes a new session with the CE console and saves the session information to local script variables. These can be cleared with the Remove-CESession cmdlet.

        .PARAMETER Version
            The version of the API this session will use. This defaults to "LATEST".

        .PARAMETER Credential
            The credential to use to connect to the CE console.

		.PARAMETER ProfileName
			The name of the profile to use.

        .PARAMETER PassThru
            If specified, the session unique identifier, the CE username, will be returned. This can be specified directly to follow-on cmdlets to specify which account the cmdlet targets.

        .EXAMPLE
            New-CESession -Credential (New-Object -TypeName System.Management.Automation.PSCredential("myfirstmigration@cloudendure.com", (ConvertTo-SecureString -String "mySecureP@$$w0rd" -AsPlainText -Force)))

            Establishes a new session to CE with the supplied email address and password. The session information is stored in script variables.

        .INPUTS
            None

        .OUTPUTS
            None or System.String

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/28/2017
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
	Param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("v12", "latest")]
		[System.String]$Version = "v12",

		[Parameter(Mandatory = $true, ParameterSetName = "Credential")]
		[ValidateNotNull()]
		[System.Management.Automation.Credential()]
		[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,
 
        [Parameter()]
        [Switch]$PassThru
	)

	DynamicParam {
		if ($Credential -eq $null -or $Credential -eq [System.Management.Automation.PSCredential]::Empty)
		{
			$Params = @(
				@{
					"Name" = "ProfileName";
					"Type" = [System.String];
					"ValidateSet" = (Get-CEProfile);
					"ParameterSets" = @("Profile");
					"Mandatory" = $true;
					"ValidateNotNullOrEmpty" = $true
				},
				@{
					"Name" = "ProfileLocation";
					"Type" = [System.String];
					"ParameterSets" = @("Profile");
					"ValidateNotNullOrEmpty" = $true
				}
			)

			$Params | ForEach-Object {
				New-Object PSObject -Property $_ 
			} | New-DynamicParameter
		}
	}

	Begin {
	}

	Process {
		if ($PSCmdlet.ParameterSetName -ieq "Profile")
		{
			$Splat = @{"ProfileName" = $PSBoundParameters["ProfileName"]}

			if (-not [System.String]::IsNullOrEmpty($PSBoundParameters["ProfileLocation"]))
			{
				$Splat.Add("ProfileLocation", $PSBoundParameters["ProfileLocation"])
			}

			$Credential = Get-CEProfile @Splat

			if ($Credential -eq $null -or $Credential -eq [System.Management.Automation.PSCredential]::Empty)
			{
				throw "Could not find the specified profile $ProfileName."
			}
		}

        [System.String]$Uri = "$script:URL/$($Version.ToLower())/login"
        [System.String]$Body = ConvertTo-Json -InputObject @{"username" = $Credential.UserName; "password" = (Convert-SecureStringToString -SecureString $Credential.Password)}
		
		[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -ContentType "application/json" -Method Post -Body $Body -SessionVariable "WebSession"

		if ($Result.StatusCode -eq 200)
		{
			$Temp = ConvertFrom-Json -InputObject $Result.Content
			$WebSession.Credentials = $Credential

			[System.String]$SummaryUri = "$script:Url/$($Version.ToLower())/ceme"

			$Summary = ConvertFrom-Json -InputObject (Invoke-WebRequest -Uri $SummaryUri -Method Get -WebSession $WebSession | Select-Object -ExpandProperty Content)

			[System.Collections.Hashtable]$Session = @{Url = $Uri; Session = $WebSession; ProjectId = $Summary.Project.Id; Version = $Version.ToLower(); CloudCredentials = $Summary.CloudCredentials; User = $Summary.User; Regions = $Summary.Regions}	

			if ($script:Sessions.ContainsKey($Summary.User.Username)) {
				$script:Sessions.Set_Item($Summary.User.Username.ToLower(), $Session)
			}
			else {
				$script:Sessions.Add($Summary.User.Username.ToLower(), $Session)
			}

			if ($PassThru) {
				Write-Output -InputObject $Summary.User.Username.ToLower()
			}
		}
	}

	End {
	}
}

Function Get-CESession {
	<#
        .SYNOPSIS
            Gets stored CE session information.

        .DESCRIPTION
            The cmdlet retrieves an established CE session by its Id, or lists all active sessions.

        .PARAMETER Session
            Specifies the unique identifier of the session to query. If this parameter is not specified, all stored sessions are returned.

        .EXAMPLE
            Get-CESession

            Gets all CE session information stored in the script variable.

        .INPUTS
            None or System.String

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
			if ($script:Sessions.ContainsKey($Session)) {
				Write-Output -InputObject $script:Sessions.Get_Item($Session)
			}
            else {
                Write-Output -InputObject $null
            }
		}
		else {
			Write-Output -InputObject $script:Sessions
		}
	}

	End {
	}
}

Function Remove-CESession {
    <#
        .SYNOPSIS
            Removes stored CE session information

        .DESCRIPTION
            The cmdlet removes CE session information generated by the New-CESession cmdlet.

        .PARAMETER Session
            Specifies the unique identifier of the session to remove. If this parameter is not specified, all stored sessions are removed.

        .EXAMPLE
            Remove-CESession

            Removes all CE session information stored in the script variable.

        .INPUTS
            None or System.String

        .OUTPUTS
            None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
	[OutputType()]
    Param(
        [Parameter(ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {
    }

    Process {
        if ($Session -eq [System.String]::Empty)
        {
			foreach ($SessionInfo in $script:Sessions.GetEnumerator())
			{
				Write-Verbose -Message "Terminating session for $($SessionInfo.Key)"
				$Uri = "$script:URL/$($SessionInfo.Value.Version)/logout"

				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -WebSession $SessionInfo.Value.Session

				if ($Result.StatusCode -ne 204)
				{
					Write-Warning -Message "Problem terminating session for $($SessionInfo.Key): $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}

            $script:Sessions = @{}

			Write-Verbose -Message "Successfully removed all sessions."
        }
        else 
        {
			$SessionInfo = Get-CESession -Session $Session
			$Uri = "$script:URL/$($SessionInfo.Version)/logout"
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -WebSession $SessionInfo.Session

			$script:Sessions.Remove($Session.ToLower())

			if ($Result.StatusCode -ne 204)
			{
				Write-Warning -Message "Problem terminating session for $Session`: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
			else
			{
				Write-Verbose -Message "Successfully removed session $Session."
			}
        }
    }

    End {
    }
}

#endregion

#region Blueprints

Function New-CEBlueprint {
	<#
		.SYNOPSIS
			Define the target machine characteristics: machine and disk types, network configuration, etc.

		.DESCRIPTION
			This cmdlet defines the target machine characteristics: machine and disk types, network configuration, etc. There can be only one blueprint per machine per region. Returns the newly created object.

		.PARAMETER Blueprint
			The blueprint to apply, the hashtable can be defined with the following data (this is presented in JSON, which the hashtable will be converted to):

			{
			  "iamRole": "string",
			  "staticIp": "string",
			  "tags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "publicIPAction": "ALLOCATE",
			  "machineName": "string",
			  "privateIPs": [
				"string"
			  ],
			  "securityGroupIDs": [
				"string"
			  ],
			  "runAfterLaunch": true,
			  "subnetsHostProject": "string",
			  "instanceType": "string",
			  "placementGroup": "string",
			  "disks": [
				{
				  "iops": 0,
				  "type": "COPY_ORIGIN",
				  "name": "string"
				}
			  ],
			  "privateIPAction": "CREATE_NEW",
			  "staticIpAction": "EXISTING",
			  "subnetIDs": [
				"string"
			  ]
			}		

		.PARAMETER IAMRole
			AWS only. The AWS IAM Role to associate with this blueprint.

		.PARAMETER InstanceType
			The instance type to launch the replica as.

		.PARAMETER PlacementGroup
			AWS Only. The placement group to launch the instance in.

		.PARAMETER PrivateIPAction
			The action for the instance's private IP address.

		.PARAMETER PrivateIPs
			If you select CUSTOM for PrivateIPAction, specify the private IPs you want associated with the instance.

		.PARAMETER PublicIPAction
			Whether to allocate an ephemeral public IP, or not. AS_SUBNET causes CloudEndure to copy this property from the source machine.

		.PARAMETER RunAfterLaunch
			AWS Only. Specify true to have the instance started after it is launched or false to leave it in a stopped state.

		.PARAMETER SecurityGroupIds
			AWS Only. The security groups that will be associated with the instance.

		.PARAMETER StaticIP
			If you select ALLOCATE for StaticIPAction, then specify Elatic IP address to associate with the instance.

		.PARAMETER SubnetIDs
			Specify the subnet Id(s) the instance will be associated with.
			
		.PARAMETER Tags
			AWS only. Tags that will be applied to the target machine.

		.PARAMETER MachineName
			The instance to create this blueprint for.

		.PARAMETER SubnetsHostProject
			GCP only. Host project for cross project network subnet.

		.PARAMETER Disks
			AWS only. Target machine disk properties. An array of objects with properties as follows:

				IOPS: Int >= 0
				TYPE: "COPY_ORIGIN", "STANDARD", "SSD", "PROVISIONED_SSD", "ST1", "SC1"
				NAME: Disk name as appears in the source machine object.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			Passes through the created object.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.EXAMPLE
			New-CEBlueprint -MachineName "MyTestMachine" -IAMRole EC2StandardInstanceProfile -SubnetIDs @("subnet-152acf5d") -SecurityGroupIDs ("sg-6053bf1f") 

			Creates a new blueprint and associates an AWS IAM Role, a specific deployment subnet, and a security group belonging to the VPC containing the subnet.

		.EXAMPLE
			New-CEBlueprint -MachineName "MyTestMachine" -SubnetIDs @("Default")
			
			Deploys the machine into the default subnet for configured target region.

		.INPUTS
            None or System.Collections.Hashtable

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

			The JSON representation of the return value:

			{
			  "iamRole": "string",
			  "staticIp": "string",
			  "tags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "publicIPAction": "ALLOCATE",
			  "machineName": "string",
			  "privateIPs": [
				"string"
			  ],
			  "securityGroupIDs": [
				"string"
			  ],
			  "runAfterLaunch": true,
			  "subnetsHostProject": "string",
			  "instanceType": "string",
			  "placementGroup": "string",
			  "machineId": "string",
			  "region": "string",
			  "disks": [
				{
				  "iops": 0,
				  "type": "COPY_ORIGIN",
				  "name": "string"
				}
			  ],
			  "privateIPAction": "CREATE_NEW",
			  "staticIpAction": "EXISTING",
			  "id": "string",
			  "subnetIDs": [
				"string"
			  ]
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/7/2017
			
	#>
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	[OutputType([System.Management.Automation.PSCustomObject])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "Blueprint")]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Blueprint = @{},

		[Parameter(ParameterSetName = "AWS")]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Tags = @{},

		[ValidateSet("ALLOCATE", "DONT_ALLOCATE", "AS_SUBENT")]
		[System.String]$PublicIPAction,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$MachineName,

		[Parameter(ParameterSetName = "AWS")]
		[System.Boolean]$RunAfterLaunch = $true,

		[Parameter(ParameterSetName = "GCP")]
		[ValidateNotNullOrEmpty()]
		[System.String]$SubnetsHostProject,

		[Parameter(ParameterSetName = "AWS")]
		[ValidateNotNull()]
		[System.Collections.Hashtable[]]$Disks,

		[Parameter()]
		[ValidateSet("CREATE_NEW", "COPY_ORIGIN", "CUSTOM_IP")]
		[System.String]$PrivateIPAction,

		[Parameter()]
		[ValidateSet("EXISTING", "DONT_CREATE", "CREATE_NEW", "IF_IN_ORIGIN")]
		[System.String]$StaticIPAction,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	DynamicParam {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $DynSessionInfo = $script:Sessions.Get_Item($Session)
			$DynSession = $Session
        }
        else {
            $DynSessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $DynSession = $DynSessionInfo.User.Username
        }

		$DynSplat = @{
			"Session" = $DynSession
		}

		if ($ProjectId -ne $null -and $ProjectId -ne [System.Guid]::Empty)
		{
			$DynSplat.Add("ProjectId", $ProjectId)
		}

		[System.Collections.Hashtable]$CECloud = Get-CETargetCloud @DynSplat | ConvertTo-Hashtable

		# Create the dictionary 
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		
		New-DynamicParameter -Name "InstanceType" -Type ([System.String]) -ValidateSet ($CECloud.InstanceTypes) -Mandatory -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

		switch ($CECloud.Cloud)
		{
			"AWS" {

				if ($CECloud.IAMRoles.Length -gt 0)
				{
					New-DynamicParameter -Name "IAMRole" -Type ([System.String]) -ParameterSets @("AWS") -ValidateSet $CECloud.IAMRoles -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
				}

				if ($CECloud.PlacementGroups.Length -gt 0)
				{
					New-DynamicParameter -Name "PlacementGroup" -Type ([System.String]) -ValidateSet ($CECloud.PlacementGroups) -ParameterSets @("AWS") -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
				}

				if ($CECloud.Subnets.Length -gt 0)
				{
					$SubnetSet = $CECloud.Subnets | Where-Object {$_.SubnetId -ne $null } | Select-Object -ExpandProperty SubnetId
					# Add default to allow user to specify the default subnet for the configured region
					$SubnetSet += "Default"

					New-DynamicParameter -Name "SubnetIDs" -Type ([System.String[]]) -ValidateSet $SubnetSet -ParameterSets @("AWS") -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
				}

				$Type = Import-UnboundParameterCode -PassThru
				$Subnets = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.Object]).Invoke($Type, @($PSCmdlet, "SubnetIDs", -1))

				$Key = [System.String]::Empty

				if ($Subnets -is [System.Array])
				{
					$Subnet = $Sunets[0]
				}
				elseif ($Subnets -is [System.String])
				{
					if (-not [System.String]::IsNullOrEmpty($Subnets))
					{
						$Key = $Subnets
					}
				}

				$Subnet = $CECloud | Select-Object -ExpandProperty Subnets | Where-Object {$_.Name -ieq $Key -or $_.Id -ieq $Key} | Select-Object -First 1 -ErrorAction SilentlyContinue

				# If the subnet is "Default", you won't be able to select a security group, so a new one will be created
				# Make sure there are security groups in this region and that we found a matching one
				if ($CECloud.SecurityGroups -ne $null -and $CECloud.SecurityGroups.Length -gt 0 -and $Subnet -ne $null)
				{
					# Get the network Id based on the selected subnet so we can get the right security groups as options
					[System.String[]]$SGSet = $CECloud | Select-Object -ExpandProperty SecurityGroups | Where-Object {$_.NetworkId -ieq $Subnet.NetworkId} | Select-Object -ExpandProperty SecurityGroupId

					New-DynamicParameter -Name "SecurityGroupIDs" -Type ([System.String[]]) -ParameterSets @("AWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
				}

				break
			}
			"GCP" {

				break
			}
			"Azure" {

				break
			}
			default {
				throw "The cloud environment $($CECloud.Cloud) is not supported by this cmdlet yet."
				break
			}
		}

		if ($PrivateIPAction -ieq "CUSTOM_IP")
		{
			New-DynamicParameter -Name "PrivateIPs" -Type ([System.String[]]) -ValidateNotNullOrEmpty -Mandatory -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
		}

		if ($StaticIPAction -ieq "EXISTING")
		{
			New-DynamicParameter -Name "StaticIP" -Type ([System.String[]]) -Mandatory -ValidateSet $CECloud.StaticIPs -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
		}

		return $RuntimeParameterDictionary
	}

	Begin {
	}

	Process {
		 $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($PSCmdlet.ParameterSetName -ne "Blueprint")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Blueprint = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the blueprint object
							if ($Item.Key -ieq "Tags")
							{
								$Tags = @()
								# We need to convert the hashtable to the tag key/value structure
								$PSBoundParameters[$Item.Key].GetEnumerator() | ForEach-Object {
									$Tags += @{"key" = $_.Key; "value" = $_.Value}
								}

								$Blueprint.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $Tags)
							}
							else {
								$Blueprint.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			if ($BluePrint.StaticIPAction -ne "EXISTING") {
                $BluePrint.StaticIP = ""
            }

            if ($BluePrint.PrivateIPAction -ne "CUSTOM_IP") {
                $BluePrint.PrivateIPs = @()
            }

			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/blueprints"

			Write-Verbose -Message "Creating new blueprint:`r`n$(ConvertTo-Json -InputObject $Blueprint)"
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Body (ConvertTo-Json -InputObject $BluePrint) -ContentType "application/json" -Method Post -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 201)
			{
				Write-Verbose -Message "Blueprint successfully created."

				if ($PassThru)
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}
			else
			{
				Write-Warning -Message "There was an issue creating the blueprint: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Get-CEBlueprint {
	<#
        .SYNOPSIS
			Gets blueprint information.

        .DESCRIPTION
			The cmdlet retrieves a specific blueprint or all the blueprints of the specified account if no Id is provided.

		.PARAMETER Id
			The blueprint Id to retrieve. If this parameter is not specified, all blueprints for the account are returned.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.
            
        .EXAMPLE
            Get-CEBlueprint

            Retrieves the blueprints of the current account.

		.EXAMPLE
            Get-CEBlueprint -Offset 1501 -Limit 10

            Retrieves the blueprints at index 1501 through 1511. This skips listing the first 1500 blueprints.

		.EXAMPLE 
			Get-CEBlueprint -Id 184142f8-a581-4c86-9285-e24382d60d55

			Gets the blueprint matching the provided Id.

        .INPUTS
            None or System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject[] or System.Management.Automation.PSCustomObject

			The JSON representation of the array:

			[
				{
				  "iamRole": "string",
				  "staticIp": "string",
				  "tags": [
					{
					  "key": "string",
					  "value": "string"
					}
				  ],
				  "publicIPAction": "ALLOCATE",
				  "machineName": "string",
				  "privateIPs": [
					"string"
				  ],
				  "securityGroupIDs": [
					"string"
				  ],
				  "runAfterLaunch": true,
				  "subnetsHostProject": "string",
				  "instanceType": "string",
				  "placementGroup": "string",
				  "machineId": "string",
				  "region": "string",
				  "disks": [
					{
					  "iops": 0,
					  "type": "COPY_ORIGIN",
					  "name": "string"
					}
				  ],
				  "privateIPAction": "CREATE_NEW",
				  "staticIpAction": "EXISTING",
				  "id": "string",
				  "subnetIDs": [
					"string"
				  ]
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/7/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = "Get")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/blueprints"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					if ($Id -ne [System.Guid]::Empty)
					{
						$Uri += "/$($Id.ToString())"
					}
					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				default {
					throw "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}
			
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				if ($Id -ne [System.Guid]::Empty)
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
				else 
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
				}
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving blueprints: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}

		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Set-CEBlueprint {
	<#
        .SYNOPSIS
			Sets a blueprint for a CE Instance.

        .DESCRIPTION
			The cmdlet updates the blueprint for a specific CE Instance. Set a parameter to an empty string to clear it from the blueprint.

			Currently, this cmdlet only supports AWS target cloud environments.

		.PARAMETER Blueprint
			The updated blueprint data to send. This hashtable only needs to contain the data that you want to update. The original blueprint will be merged with this one.

			The available configuration items are:

			{
			  "iamRole": "string",
			  "staticIp": "string",
			  "tags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "publicIPAction": "ALLOCATE",		# "ALLOCATE" "DONT_ALLOCATE" "AS_SUBNET"
			  "machineName": "string",
			  "privateIPs": [
				"string"
			  ],
			  "securityGroupIDs": [
				"string"
			  ],
			  "runAfterLaunch": true,
			  "subnetsHostProject": "string",
			  "instanceType": "string",
			  "placementGroup": "string",
			  "disks": [
				{
				  "iops": 0,
				  "type": "COPY_ORIGIN",		# "COPY_ORIGIN" "STANDARD" "SSD" "PROVISIONED_SSD" "ST1" "SC1"
				  "name": "string"
				}
			  ],
			  "privateIPAction": "CREATE_NEW",	# "CREATE_NEW" "COPY_ORIGIN" "CUSTOM_IP"
			  "staticIpAction": "EXISTING",		# "EXISTING" "DONT_CREATE" "CREATE_NEW" "IF_IN_ORIGIN"
			  "subnetIDs": [
				"string"
			  ]
			}

		.PARAMETER IAMRole
			AWS Only. The AWS IAM Role to associate with this blueprint.

		.PARAMETER InstanceType
			The instance type to launch the replica as.

		.PARAMETER PlacementGroup
			AWS Only. The placement group to launch the instance in.

		.PARAMETER PrivateIPAction
			The action for the instance's private IP address.

		.PARAMETER PrivateIPs
			If you select CUSTOM for PrivateIPAction, specify the private IPs you want associated with the instance.

		.PARAMETER PublicIPAction
			Whether to allocate an ephemeral public IP, or not. AS_SUBNET causes CloudEndure to copy this property from the source machine.

		.PARAMETER RunAfterLaunch
			AWS Only. Specify true to have the instance started after it is launched or false to leave it in a stopped state.

		.PARAMETER SecurityGroupIds
			AWS Only. The security groups that will be associated with the instance.

		.PARAMETER MachineName
			The name of the replica instance.

		.PARAMETER StaticIP
			If you select ALLOCATE for StaticIPAction, then specify Elatic IP address to associate with the instance.

		.PARAMETER SubnetIDs
			AWS Only. Specify the subnet Id(s) the instance will be associated with.

		.PARAMETER SubnetsHostProject
			GCP Only. Host project for cross project network subnet.
            
		.PARAMETER Tags
			AWS Only. The tags that will be associated with the instance.

		.PARAMETER Disks
			AWS only. Target machine disk properties. An array of objects with properties as follows:

				IOPS: Int >= 0
				TYPE: "COPY_ORIGIN", "STANDARD", "SSD", "PROVISIONED_SSD", "ST1", "SC1"
				NAME: Disk name as appears in the source machine object.

		.PARAMETER InstanceId
			The id of the CE instance whose blueprint you want to update.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			The updated blueprint will be returned to the pipeline.

        .EXAMPLE
            Set-CEBlueprint -InstanceId 47d842b8-ebfa-4695-90f8-fb9ab686c708 -Blueprint @{"IAMRole" = "EC2-InstanceProfile-Public"}

			This adds or updates the IAMRole property for the blueprint to "EC2-InstanceProfile-Public" for the CE instance identified by 47d842b8-ebfa-4695-90f8-fb9ab686c708.

		.EXAMPLE
			Set-CEBlueprint -InstanceId 47d842b8-ebfa-4695-90f8-fb9ab686c708 -IAMRole "EC2-InstanceProfile-Public"

			This adds or updates the IAMRole property for the blueprint to "EC2-InstanceProfile-Public" for the CE instance identified by 47d842b8-ebfa-4695-90f8-fb9ab686c708.

        .INPUTS
            None or System.Collections.Hashtable

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

			The JSON representation of the return value:
			{
			  "iamRole": "string",
			  "staticIp": "string",
			  "tags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "publicIPAction": "ALLOCATE",
			  "machineName": "string",
			  "privateIPs": [
				"string"
			  ],
			  "securityGroupIDs": [
				"string"
			  ],
			  "runAfterLaunch": true,
			  "subnetsHostProject": "string",
			  "instanceType": "string",
			  "placementGroup": "string",
			  "machineId": "string",
			  "region": "string",
			  "disks": [
				{
				  "iops": 0,
				  "type": "COPY_ORIGIN",
				  "name": "string"
				}
			  ],
			  "privateIPAction": "CREATE_NEW",
			  "staticIpAction": "EXISTING",
			  "id": "string",
			  "subnetIDs": [
				"string"
			  ]
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/7/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
    [OutputType([PSCustomObject])]
    Param(
		[Parameter(Mandatory = $true)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid]$InstanceId = [System.Guid]::Empty,

		[Parameter(Mandatory = $true, ParameterSetName = "Blueprint", ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Blueprint = @{},

		[Parameter()]
		[ValidateSet("COPY_ORIGIN", "CREATE_NEW", "CUSTOM_IP")]
		[System.String]$PrivateIPAction,

		[Parameter()]
		[ValidateSet("ALLOCATE", "DONT_ALLOCATE", "AS_SUBNET")]
		[System.String]$PublicIPAction,

		[Parameter(ParameterSetName = "AWS")]
		[System.Boolean]$RunAfterLaunch,

		[Parameter()]
		[ValidateSet("DONT_CREATE", "CREATE_NEW", "EXISTING", "IF_IN_ORIGIN")]
		[System.String]$StaticIPAction,

		[Parameter(ParameterSetName = "AWS")]
		[System.Collections.Hashtable]$Tags,

		[Parameter(ParameterSetName = "AWS")]
		[ValidateNotNull()]
		[System.Collections.Hashtable[]]$Disks,

		[Parameter(ParameterSetName = "GCP")]
		[System.String]$SubnetsHostProject,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$MachineName,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

		[Parameter()]
		[Switch]$PassThru
    )

	DynamicParam {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $DynSessionInfo = $script:Sessions.Get_Item($Session)
			$DynSession = $Session
        }
        else {
            $DynSessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $DynSession = $DynSessionInfo.User.Username
        }

		$DynSplat = @{
			"Session" = $DynSession
		}

		if ($ProjectId -ne $null -and $ProjectId -ne [System.Guid]::Empty)
		{
			$DynSplat.Add("ProjectId", $ProjectId)
		}

		# Create the dictionary 
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		
		if ($InstanceId -ne $null -and $InstanceId -ne [System.Guid]::Empty) 
		{
			[System.Collections.Hashtable]$CECloud = Get-CETargetCloud @DynSplat | ConvertTo-Hashtable
			[System.Collections.Hashtable]$ExistingBlueprint = Get-CEBlueprint -Id $InstanceId @DynSplat | ConvertTo-Hashtable

			#region InstanceType

			New-DynamicParameter -Name "InstanceType" -Type ([System.String]) -ValidateSet $CECloud.InstanceTypes -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

			#endregion

			switch ($CECloud.Cloud)
			{
				"AWS" {

					#region IAMRole

					$IAMSet = $CECloud.IAMRoles
					$IAMSet += [System.String]::Empty

					New-DynamicParameter -Name "IAMRole" -Type ([System.String]) -ParameterSets @("AWS") -ValidateSet $IAMSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
        
					#endregion

					if ($CECloud.PlacementGroups.Length -gt 0)
					{
						#region PlacementGroup

						$PlacementSet = $CECloud.PlacementGroups
						$PlacementSet += [System.String]::Empty

						New-DynamicParameter -Name "PlacementGroup" -Type ([System.String]) -ParameterSets @("AWS") -ValidateSet $PlacementSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
        
						#endregion
					}
		
					if ($CECloud.Subnets.Length -gt 0) 
					{
						#region SubnetIDs

						$SubnetSet = $CECloud.Subnets | Where-Object {$_.SubnetId -ne $null } | Select-Object -ExpandProperty SubnetId
						$SubnetSet += "Default"

						New-DynamicParameter -Name "SubnetIDs" -Type ([System.String[]]) -ParameterSets @("AWS") -ValidateSet $SubnetSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion
					}

					if ($PrivateIPAction -ieq "CUSTOM_IP" -or $ExistingBlueprint.PrivateIPAction -ieq "CUSTOM_IP")
					{
						#region PrivateIPs

						New-DynamicParameter -Name "PrivateIPs" -Type ([System.String[]]) -Mandatory:($PrivateIPAction -ieq "CUSTOM_IP") -ParameterSets @("AWS") -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion
					}

					$Type = Import-UnboundParameterCode -PassThru
					$Subnets = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.Object]).Invoke($Type, @($PSCmdlet, "SubnetIDs", -1))

					$Key = [System.String]::Empty

					if ($Subnets -is [System.Array])
					{
						$Key = $Subnets[0]
					}
					elseif ($Subnets -is [System.String])
					{
						if (-not [System.String]::IsNullOrEmpty($Subnets))
						{
							$Key = $Subnets
						}
					}

					$Subnet = $CECloud | Select-Object -ExpandProperty Subnets | Where-Object {$_.Name -ieq $Key -or $_.Id -ieq $Key} | Select-Object -First 1 -ErrorAction SilentlyContinue

					if ($Subnet -ne $null -or ($ExistingBlueprint.SubnetIDs -ne $null -and $ExistingBlueprint.SubnetIDs.Length -gt 0))
					{
						# Set the network Id based on the selected subnet so we can get the right security groups as options
						if ($Subnet -ne $null) {
							$VpcId = $Subnet.NetworkId
						}
						else {
							$VpcId = $CECloud | Select-Object -ExpandProperty Subnets | Where-Object {$_.Id -ieq $ExistingBlueprint.SubnetIDs[0]} | Select-Object -First 1 -ErrorAction SilentlyContinue
						}

						#region SecurityGroups

						$SGSet = $CECloud.SecurityGroups | Where-Object {$_.NetworkId -ieq $VpcId}
						$SGSet += [System.String]::Empty

						New-DynamicParameter -Name "SecurityGroupIDs" -Type ([System.String[]]) -ParameterSets @("AWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
        
						#endregion
					}

					break
				}
				"GCP" {

					break
				}
				"Azure" {

					break
				}
				default {
					throw "The cloud environment $($CECloud.Cloud) is not supported by this cmdlet yet."
				}
			}

			if ($StaticIPAction -ieq "EXISTING" -or $ExistingBlueprint.StaticIPAction -ieq "EXISTING")
			{
				#region EIP

				New-DynamicParameter -Name "StaticIP" -Type ([System.String[]]) -Mandatory:($StaticIPAction -ieq "EXISTING") -ValidateSet $CECloud.StaticIPs -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

				#endregion
			}
		}

		return $RuntimeParameterDictionary
	}

    Begin {      
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{	 
			[System.Collections.Hashtable]$SessSplat = @{
				"Session" = $Session
			}

			if ($ProjectId -ne [System.Guid]::Empty)
			{
				$SessSplat.Add("ProjectId", $ProjectId)
			}

			[System.Collections.Hashtable]$ExistingBlueprint = Get-CEBlueprint -Id $InstanceId @SessSplat | ConvertTo-Hashtable

			# If a blueprint hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Blueprint")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Blueprint = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the blueprint object

							if ($Item.Key -ieq "Tags")
							{
								$Tags = @()
								# We need to convert the hashtable to the tag key/value structure
								$PSBoundParameters[$Item.Key].GetEnumerator() | ForEach-Object {
									$Tags += @{"key" = $_.Key; "value" = $_.Value}
								}

								$Blueprint.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $Tags)
							}
							else {
								$Blueprint.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			# Merge the original and new blueprint
			[System.Collections.Hashtable]$NewBluePrint = Merge-HashTables -Source $ExistingBlueprint -Update $Blueprint

            if ($NewBluePrint.StaticIPAction -ne "EXISTING") {
                $NewBluePrint.StaticIP = ""
            }

            if ($NewBluePrint.PrivateIPAction -ne "CUSTOM_IP") {
                $NewBluePrint.PrivateIPs = @()
            }

			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/blueprints/$($NewBluePrint.Id)"

			$ConfirmMessage = "Are you sure you want to update the blueprint configuration?"

			$WhatIfDescription = "Updated blueprint to $(ConvertTo-Json -InputObject $NewBluePrint)"
			$ConfirmCaption = "Update Blueprint"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Updating blueprint to :`r`n$(ConvertTo-Json -InputObject $NewBluePrint)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Body (ConvertTo-Json -InputObject $NewBluePrint) -ContentType "application/json" -Method Patch -WebSession $SessionInfo.Session
        
				if ($Result.StatusCode -eq 200)
				{
					Write-Verbose -Message "Blueprint successfully modified."

					if ($PassThru)
					{
						Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
					}
				}
				else
				{
					Write-Warning -Message "There was an issue updating the blueprint: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

#endregion

#region Replication Configuration

Function Get-CEMachineRecoveryPoints {
	<#
		.SYNOPSIS
			Returns the list of available recovery points for the specified machine.

		.DESCRIPTION
			Returns the list of available recovery points for the specified machine.

			This is only available if the license type is DR.

		.PARAMETER InstanceId
			The CE instance to retrieve recovery points in time information about.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

        .EXAMPLE
			Get-CEMachineRecoveryPoints -InstanceId 47d842b8-ebfa-4695-90f8-fb9ab686c708

			This gets a list of the recovery points for the specified instance.

		.EXAMPLE
			Get-CEMachineRecoveryPoints -InstanceId 47d842b8-ebfa-4695-90f8-fb9ab686c708 -Offset 1501 -Limit 50

			This gets a list of the recovery points for the specified instance from index 1501 to 1551.

        .INPUTS
            System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject[]
			
			The JSON representation of the array:
			[
				{
					"id": "string",
					"dateTime": "2017-09-06T01:39:46Z"
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/7/2017
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$InstanceId,

		[Parameter()]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter()]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/$InstanceId/pointsintime"

			if ($Offset -gt 0 -or $Limit -lt 1500)
			{
				$QueryString = [System.String]::Empty

				if ($Offset -gt 0)
				{
					$QueryString += "&offset=$Offset"
				}

				if ($Limit -lt 1500)
				{
					$QueryString += "&limit=$Limit"
				}

				# Remove the first character which is an unecessary ampersand
				$Uri += "?$($QueryString.Substring(1))"
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content).Items
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the recovery points: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {

	}
}

Function New-CEReplicationConfiguration {
	<#
		.SYNOPSIS
			Creates a new CE replication configuration.

		.DESCRIPTION
			This cmdlet is used to create a new CE replication configuration for a specific CE account.

		.PARAMETER ProxyUrl
			The full URI for a proxy (schema, username, password, domain, port) if required for the CloudEndure agent. Leave blank to not use a proxy.

		.PARAMETER SubnetId
			Subnet where replication servers will be created.

		.PARAMETER UsePrivateIp
			Should the CloudEndure agent access the replication server using its private IP address. Set this parameter to true to use a VPN, DirectConnect, ExpressRoute, or GCP Carrier Interconnect/Direct Peering.

		.PARAMETER VolumeEncryptionKey
			AWS only. ARN to private key for volume encryption.

		.PARAMETER ReplicationTags
			AWS only. Tags that will be applied to every cloud resource created in the CloudEndure staging area.

		.PARAMETER SubnetHostProject
			GCP only. Host project of cross project network subnet.

		.PARAMETER ReplicatorSecurityGroupIDs
			AWS only. The security groups that will be applied to the replication servers.

		.PARAMETER Config
			You can provide a replication config with these properties:

			{
			  "volumeEncryptionKey": "string",
			  "replicationTags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "subnetHostProject": "string",
			  "replicatorSecurityGroupIDs": [
				"string"
			  ],
			  "usePrivateIp": true,
			  "proxyUrl": "string",
			  "cloudCredentials": "string",
			  "subnetId": "string",
			  "region" : "string"
			}

            You cannot specify an updated Source as part of the config file, you must specify that separately.

		.PARAMETER Source
			The source identifier for replication. 

		.PARAMETER Target
			The destination indentifier for replication.			

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER PassThru
			Specify to return the updated config to the pipeline.

		.EXAMPLE
			New-CEReplicationConfiguration -SubnetId "subnet-421d476c" -Target "us-east-1" -Source "Generic"

			Creates a new CE replication configuration to specify that replication will be sent to AWS US-East-1, replication servers should be deployed in subnet-421d476c, and the source is a generic location.

		.INPUTS
            None or System.Collections.Hashtable

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

			The JSON representation of the return value:
			{
			  "volumeEncryptionKey": "string",
			  "replicationTags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "subnetHostProject": "string",
			  "replicatorSecurityGroupIDs": [
				"string"
			  ],
			  "usePrivateIp": true,
			  "region": "string",
			  "proxyUrl": "string",
			  "cloudCredentials": "string",
			  "subnetId": "string",
			  "id": "string"
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
    Param(
		[Parameter(ParameterSetName = "Config", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Config = @{},

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]$ProxyUrl,

        [Parameter()]
        [System.Boolean]$UsePrivateIp = $false,

        [Parameter(ParameterSetName = "AWS")]
		[ValidateNotNullOrEmpty()]
        [System.String]$VolumeEncryptionKey,

		[Parameter(ParameterSetName = "AWS")]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$ReplicationTags,

		[Parameter(ParameterSetName = "GCP")]
		[ValidateNotNullOrEmpty()]
		[System.String]$SubnetHostProject,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

	DynamicParam {

        if (-not [System.String]::IsNullOrEmpty($Session)) {
			$DynSessionInfo = $script:Sessions.Get_Item($Session)
			$DynSession = $Session
		}
		else {
			$DynSessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$DynSession = $DynSessionInfo.User.Username
		}

		$DynSplat = @{
			"Session" = $DynSession
		}

		if ($ProjectId -ne $null -and $ProjectId -ne [System.Guid]::Empty)
		{
			$DynSplat.Add("ProjectId", $ProjectId)
		}

		[PSCustomObject[]]$CERegions = Get-CECloudRegion @DynSplat 

        # Create the dictionary 
		$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		#region Source - The source isn't defined as part of the replication config

		New-DynamicParameter -Name "Source" -Type ([System.String]) -ValidateSet (($CERegions | Select-Object -ExpandProperty Name) + "Generic") -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

		#endregion
		
		# If a config wasn't provided, add target specific parameters
		if ($Config -eq $null -or $Config -eq @{})
		{
			#region Target

			[System.Collections.ArrayList]$TargetSet = $CERegions | Select-Object -ExpandProperty Name
			$TargetSet.Remove("Generic")

			New-DynamicParameter -Name "Target" -Type ([System.String]) -ValidateSet $TargetSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

			#endregion

			# Import the unbound parameter checking code from HostUtilities
			$Type = Import-UnboundParameterCode -PassThru
			[System.String]$TargetRegionName = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "Target", -1))

			if (-not [System.String]::IsNullOrEmpty($TargetRegionName))
			{
				$Region = $CERegions | Where-Object {$_.Name -ieq $TargetRegionName}

				if ($Region -ne $null)
				{
					$TargetRegion = $Region | Select-Object -First 1 
					$RegionSubnets = $TargetRegion | Select-Object -ExpandProperty Subnets

					#region SubnetId					

					# Allow user to specify either the long name or the subnet id in the parameter
					[System.String[]]$SubnetSet = $TargetRegion | Select-Object -First 1 -ExpandProperty Subnets | Select-Object -ExpandProperty Name
					$SubnetSet += $CERegions | Where-Object {$_.Id -ieq $TargetRegionId } | Select-Object -First 1 -ExpandProperty Subnets | Select-Object -ExpandProperty SubnetId

					New-DynamicParameter -Name "SubnetId" -Type ([System.String]) -ValidateSet $SubnetSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

					#endregion

					[System.String]$Cloud = $CERegions | Where-Object {$_.Id -ieq $TargetRegionId} | Select-Object -First 1 -ExpandProperty Cloud

					# ReplicatorSecurityGroupIDs is only an option for AWS as is VolumeEncryptionKey
					if ($Cloud -ieq "AWS")
					{
						#region KMS

						$KMSSet = $TargetRegion | Select-Object -ExpandProperty VolumeEncryptionKeys | Where-Object {$_.KeyArn -ne $null} | Select-Object -ExpandProperty KeyArn
						$KMSSet += "Default"

						New-DynamicParameter -Name "VolumeEncryptionKey" -ValidateSet $KMSSet -ParameterSets @("AWS") -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion

						[System.String]$SubnetId = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "SubnetId", -1))

						if (-not [System.String]::IsNullOrEmpty($SubnetId))
						{
							# Since we allowed the user to specify either the subnetid or the long name, we need to check which one
							# was specified

							$VpcId = $RegionSubnets | Where-Object {$_.Name -ieq $SubnetId -or $_.Id -ieq $SubnetId} | Select-Object -ExpandProperty NetworkId -ErrorAction SilentlyContinue

							# If we found the subnet, and we found the VPC, populate security groups
							# If it wasn't found, either the subnet provided was "Default" or not a recognized value
							if (-not [System.String]::IsNullOrEmpty($VpcId))
							{
								#region SecurityGroups

								$SGSet = $TargetRegion | Select-Object -ExpandProperty SecurityGroups | Where-Object {$_.NetworkId -ieq $VpcId} | Select-Object -ExpandProperty SecurityGroupId
								$SGSet += [System.String]::Empty

								New-DynamicParameter -Name "ReplicatorSecurityGroupIDs" -Type ([System.String]) -ParameterSets @("AWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

								#endregion
							}
						}
					}
				}
			}
		}
        
        return $RuntimeParameterDictionary
	}

	Begin {		
	}

	Process {		
		# Get all of the dynamic params into variables
		[System.String]$Target = $PSBoundParameters["Target"]
		[System.String]$Source = $PSBoundParameters["Source"]
		
		# Make sure a target or destination was specified
		if ([System.String]::IsNullOrEmpty($Source) -and [System.String]::IsNullOrEmpty($Target) -and [System.String]::IsNullOrEmpty($Config["region"]))
		{
			throw "A new source and/or target must be specified to create a new replication configuration."
		}

		$SessionInfo = $null

		if (-not [System.String]::IsNullOrEmpty($Session)) {
			$SessionInfo = $script:Sessions.Get_Item($Session)
		}
		else {
			$SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
		}

		if ($SessionInfo -ne $null) 
		{
			[System.Collections.Hashtable]$SessSplat = @{
				"Session" = $Session
			}

			if ($ProjectId -ne [System.Guid]::Empty)
			{
				$SessSplat.Add("ProjectId", $ProjectId)
			}

			[PSCustomObject[]]$CERegions = Get-CECloudRegion @SessSplat 

			# This is the default set of properties we can specify for a new replication config
			$DefaultConfig = @{
				"cloudCredentials" = "$($SessionInfo.CloudCredentials)";
                "region" = "";
                "subnetId" = "";
				"subnetHostProject" = "";
                "replicatorSecurityGroupIDs" = @();
                "volumeEncryptionKey" = "";
                "replicationTags" = @();
                "usePrivateIp" = $false;
                "proxyUrl" = ""
            }
                    
			# If a config hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Config")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Config = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
                {
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the config
							
							if ($Item.Key -ieq "ReplicationTags")
							{
								$Tags = @()
								# We need to convert the hashtable to the tag key/value structure
								$PSBoundParameters[$Item.Key].GetEnumerator() | ForEach-Object {
									$Tags += @{"key" = $_.Key; "value" = $_.Value}
								}

								$Config.Add("replicationTags", $Tags)
							}
                            # The friendly name or the id of the subnet was provided at the command line
                            elseif ($Item.Key -ieq "SubnetId") 
							{
								[System.String]$SubnetId = $CERegions | 
									Where-Object {$_.Name -ieq $Target} | 
									Select-Object -ExpandProperty Subnets | 
									Where-Object {$_.Name -ieq $PSBoundParameters["SubnetId"] -or $_.Id -ieq $PSBoundParameters["SubnetId"]} | 
									Select-Object -First 1 -ExpandProperty Id

								if (-not [System.String]::IsNullOrEmpty($SubnetId))
								{
									$Config.Add("subnetId", $SubnetId)
								}
							}
							elseif ($Item.Key -ieq "Source")
							{
								$SourceId = (($CERegions | Select-Object -Property Name,Id) + [PSCustomObject]@{"Name" = "Generic"; "Id" = $script:CloudIds["Generic"]}) | Where-Object {$_.Name -ieq $PSBoundParameters[$Item.Key]} | Select-Object -ExpandProperty Id -First 1
								$Config.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $SourceId)
							}
							elseif ($Item.Key -ieq "Target")
							{
								$TargetId = $CERegions | Where-Object {$_.Name -ieq $PSBoundParameters[$Item.Key]} | Select-Object -First 1 -ExpandProperty Id
								$Config.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $TargetId)
							}
							else 
							{
								$Config.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			# Merge the updated parameters specified with the default settings
			# This ensures our request has all required properties, even if some are blank
            $Config = Merge-Hashtables -Source $DefaultConfig -Update $Config

			# We need the project to see the original source
            [System.Collections.Hashtable]$CurrentProject = Get-CEProject @SessSplat | ConvertTo-Hashtable

			# We need the current replication config to see the original target
            [System.collections.Hashtable]$CurrentConfig = Get-CEReplicationConfiguration -Id $CurrentProject["replicationConfiguration"] @SessSplat | ConvertTo-Hashtable

			# Build the confirmation messages with warnings about updates to source and destination
            $ConfirmMessage = "The action you are about to perform is destructive!"

            if (-not [System.String]::ISNullOrEmpty($Source))
            {        
				$OriginalSrc = $CurrentProject["source"]
                $OriginalSource = ($CERegions + [PSCustomObject]@{"Name" = "Generic"; "Id" = $script:CloudIds["Generic"]}) | Where-Object {$_.Id -ieq $OriginalSrc } | Select-Object -First 1 -ExpandProperty Name
                    
                # Do this second so we don't overwrite the original source for the confirm message
				# This will set the updated source for the PATCH request
                $CurrentProject["source"] = $CERegions | Where-Object {$_.Name -ieq $Source} | Select-Object -First 1 -ExpandProperty Id

                $ConfirmMessage += "`r`n`r`nChanging your Live Migration Source from $OriginalSource to $Source will cause all current instances to be disconnected from CloudEndure: you will need to reinstall the CloudEndure Agent on all the instances and data replication will restart from zero."
            }

            if (-not [System.String]::IsNullOrEmpty($Target) -or -not [System.String]::IsNullOrEmpty($Config["region"]))
            {
				# If a config with a region wasn't specified, get it from the Target specified
				# The RegionMapping table was built during the dynamic params evaluation
				if ([System.String]::IsNullOrEmpty($Config["region"]))
				{
					$Config["region"] = $CERegions | Where-Object {$_.Name -ieq $Target} | Select-Object -First 1 -ExpandProperty Id
				}

                $OriginalTarget = $CERegions | Where-Object {$_.Id -ieq $CurrentConfig["region"] } | Select-Object -First 1 -ExpandProperty Name

                $ConfirmMessage += "`r`n`r`nChanging your Live Migration Target from $OriginalTarget to $Target will cause all current instances to be disconnected from CloudEndure: you will need to reinstall the CloudEndure Agent on all the instances and data replication will restart from zero."
            }

            $ConfirmMessage += "`r`n`r`nAre you sure you want to continue?"
			$WhatIfDescription = "New replication configuration created: $(ConvertTo-Json -InputObject $Config)"
			$ConfirmCaption = "Create New Replication Configuration"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				if ($ProjectId -eq [System.Guid]::Empty)
				{
					$ProjectId = $SessionInfo.ProjectId
				}

                # Send the post request to create a new replication configuration if a new target region was specified
                if (-not [System.String]::IsNullOrEmpty($Config["region"]))
                {
					if ($Config["region"] -ne $Currentconfig["region"] )
					{
						Write-Verbose -Message "Sending config $(ConvertTo-Json $Config)"
						[System.String]$PostUri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replicationConfigurations"
						[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$PostResult = Invoke-WebRequest -Uri $PostUri -Method Post -Body (ConvertTo-Json -InputObject $Config) -ContentType "application/json" -WebSession $SessionInfo.Session

						if ($PostResult.StatusCode -ne 201)
						{
							# Make sure we don't send the patch request if this failed
							throw "Failed to create new Replication Configuration with error: $($PostResult.StatusCode) $($PostResult.StatusDescription) - $($PostResult.Content)"
						}
						else
						{
							Write-Verbose -Message $PostResult.Content
							# Update the project with the new replication configuration Id to supply in the PATCH request
							$CurrentProject["replicationConfiguration"] = (ConvertFrom-Json -InputObject $PostResult.Content).Id
						}
					}
					else
					{
						Write-Warning -Message "The specified target region $OriginalTarget is the same as the current region, no update made."
					}
                }

				# Make sure a new source that was different than the old one was specified or that the target region is new meaning that the replication configuration
				# id has changed
				if ((-not [System.String]::IsNullOrEmpty($Source) -and $CurrentProject["source"] -ne $OriginalSrc) -or $Config["region"] -ne $Currentconfig["region"])
				{
					# Send the patch request to update the project data with the new source, if provided, or the new replication configuration
					# At least 1 of them changed, so we'll always need to send this patch request
					[System.String]$PatchUri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId"

					# Don't specify the type of project in the update, it's fixed based on the type of account CE sets up
					$CurrentProject.Remove("type")

					Write-Verbose -Message "Sending updated project $(ConvertTo-Json $CurrentProject)"
					[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$PatchResult = Invoke-WebRequest -Uri $PatchUri -Method Patch -Body (ConvertTo-Json -InputObject $CurrentProject) -ContentType "application/json" -WebSession $SessionInfo.Session

					if ($PatchResult.StatusCode -ne 200)
					{
						throw "The project information patch request failed, you will need to retry updating this item if you selected a different target environment as the project and replication configurations are now out of sync."
					}
					else 
					{
						Write-Verbose -Message $PatchResult.Content
					}
				}
				else
				{
					Write-Warning -Message "Either no new source specified or no new target specified."
				}
            }
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Get-CEReplicationConfiguration {
	<#
        .SYNOPSIS
           Gets the replication configuration.

        .DESCRIPTION
            The cmdlet retrieves information about the replication configuration.

		.PARAMETER Id
			The id of the replication configuration to retrieve. If this is not specified, all replication configurations will be returned.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEReplicationConfiguration

            Retrieves the replication configuration of the current account.

        .INPUTS
            None or System.Guid

        .OUTPUTS
			System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			The JSON representation of the array:
			[
				{
				  "volumeEncryptionKey": "string",
				  "replicationTags": [
					{
					  "key": "string",
					  "value": "string"
					}
				  ],
				  "subnetHostProject": "string",
				  "replicatorSecurityGroupIDs": [
					"string"
				  ],
				  "usePrivateIp": true,
				  "region": "string",
				  "proxyUrl": "string",
				  "cloudCredentials": "string",
				  "subnetId": "string",
				  "id": "string"
				}
			]
			
        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName="Get")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{	
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replicationConfigurations"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					# This REST API doesn't support supplying the Id as part of the URL

					$Offset = 0
					$Limit = 1500

					[System.UInt32]$Count = $Limit
					[System.Int32]$ResultCount = 0
					[System.Boolean]$Found = $false
					$ReplConfig = $null

					# Go until the results returned are less than the specified limit or the loop
					# breaks when the config is found
					while ($Count -ge $ResultCount)
					{
						Write-Verbose -Message "Querying replication configurations from $Offset to $($Offset + $Limit)."

						[System.String]$QueryString = "?offset=$Offset&limit=$Limit"
						[System.String]$TempUri = "$Uri$QueryString"
						[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $TempUri -Method Get -WebSession $SessionInfo.Session

						if ($Result.StatusCode -eq 200)
						{
							[PSCustomObject[]]$Content = ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
							$ResultCount = $Content.Length

							$ReplConfig = $Content | Where-Object {$_.Id -ieq $Id.ToString()}

							if ($ReplConfig -ne $null)
							{
								Write-Output -InputObject ([PSCustomObject]($ReplConfig | Select-Object -First 1))
								$Found = $true
								break
							}
							else
							{
								$Offset += $Limit
							}
						}
						else
						{
							Write-Warning -Message "There was an issue retrieving replication configurations: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
							# Break out of the loop
							break
						}
					}

					if (-not $Found)
					{
						throw "The replication configuration with Id $Id was not found."
					}

					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}

					[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

					if ($Result.StatusCode -eq 200)
					{
						Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
					}
					else
					{
						Write-Warning -Message "There was an issue retrieving the replication configurations: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
					}

					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Set-CEReplicationConfiguration {
    <#
		.SYNOPSIS
			Sets the CE replication configuration.

		.DESCRIPTION
			This cmdlet is used to set the CE replication configuration options for a specific CE account.

			Modifying volumeEncryptionKey or modifying cloudCredentials to ones matching a different cloud account will result in replication restarting from initial sync.

			This cmdlet will let you specify both Config and some other values, like -UsePrivateIp. If you specify any additional configuration parameters, they will be ignored.

		.PARAMETER Id
			The replication configuration id.

		.PARAMETER ProxyUrl
			The full URI for a proxy (schema, username, password, domain, port) if required for the CloudEndure agent. Leave blank to not use a proxy.

		.PARAMETER SubnetId
			Specify the subnet Id that the replication servers will be launched in.

		.PARAMETER UsePrivateIp
			Set this parameter to true to use a VPN, DirectConnect, ExpressRoute, or GCP Carrier Interconnect/Direct Peering.

		.PARAMETER VolumeEncryptionKey
			AWS only. ARN to private key for volume encryption.

		.PARAMETER ReplicationTags
			AWS Only. Specify the tags that will be applied to CE replication resources.

		.PARAMETER SubnetHostProject
			GCP only. Host project of cross project network subnet.

		.PARAMETER Config
			You can provide a replication config with these properties:

			{
			  "volumeEncryptionKey": "string",
			  "replicationTags": [
				{
				  "key": "string",
				  "value": "string"
				}
			  ],
			  "subnetHostProject": "string",
			  "replicatorSecurityGroupIDs": [
				"string"
			  ],
			  "usePrivateIp": true,
			  "proxyUrl": "string",
			  "cloudCredentials": "string",
			  "subnetId": "string"
			}

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			Specify to return the updated config to the pipeline.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.EXAMPLE
			Set-CEReplicationConfiguration -Id 8cdf36d4-6668-44a9-9cfe-16cb93538a79 -SubnetId "subnet-421d476c"

			Updates the existing replication configuration to specify that replication servers should be deployed in subnet-421d476c.

		.INPUTS
            None

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid]$Id,

		[Parameter(ParameterSetName = "Config", Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Config = @{},

        [Parameter()]
        [ValidateNotNull()]
        [System.String]$ProxyUrl,

        [Parameter()]
        [System.Boolean]$UsePrivateIp,

		[Parameter(ParameterSetName = "AWS")]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$ReplicationTags,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

	DynamicParam {
		if ($Config -eq $null -or $Config -eq @{})
		{
			if (-not [System.String]::IsNullOrEmpty($Session)) {
				$DynSessionInfo = $script:Sessions.Get_Item($Session)
				$DynSession = $Session
			}
			else {
				$DynSessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
				$DynSession = $DynSessionInfo.User.Username
			}

			$DynSplat = @{
				"Session" = $DynSession
			}

			if ($ProjectId -ne $null -and $ProjectId -ne [System.Guid]::Empty)
			{
				$DynSplat.Add("ProjectId", $ProjectId)
			}

			[System.Collections.Hashtable]$CECloud = Get-CETargetCloud @DynSplat | ConvertTo-Hashtable

			# Create the dictionary 
			$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		
			if ($Id -ne $null -and $Id -ne [System.Guid]::Empty) 
			{
				if ($CECloud.Subnets.Length -gt 0) 
				{
					#region SubnetId

					# Allow user to specify either the long name or the subnet id in the parameter
					[System.String[]]$SubnetSet = $CECloud | Select-Object -ExpandProperty Subnets | Select-Object -ExpandProperty Name
					$SubnetSet += $CECloud | Select-Object -ExpandProperty Subnets | Select-Object -ExpandProperty SubnetId

					New-DynamicParameter -Name "SubnetId" -Type ([System.String]) -ParameterSets @("AWS") -ValidateSet $SubnetSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

					#endregion
				}

				switch ($CECloud.Cloud)
				{
					"AWS" {

						if ($CECloud.VolumeEncryptionKeys.Length -gt 0)
						{
							#region KMS

							[System.Collections.ArrayList]$KMSSet = $CECloud | Select-Object -ExpandProperty VolumeEncryptionKeys | Where-Object {$_.KeyArn -ne $null } | Select-Object -ExpandProperty KeyArn
							$KMSSet += "Default"
							$KMSSet += [System.String]::Empty

							New-DynamicParameter -Name "VolumeEncryptionKey" -Type ([System.String[]]) -ParameterSets @("AWS") -ValidateSet $KMSSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

							#endregion
						}

						$Type = Import-UnboundParameterCode -PassThru
						# The subnet Id here is the verbose version of the subnet selected by the user
						[System.String]$SubnetId = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "SubnetId", -1))
			
						if ([System.String]::IsNullOrEmpty($SubnetId))
						{
							[System.Collections.Hashtable]$ExistingConfig = Get-CEReplicationConfiguration -Id $Id @DynSplat | ConvertTo-Hashtable

							if (-not [System.String]::IsNullOrEmpty($ExistingConfig.SubnetId))
							{
								$SubnetId = $ExistingConfig.SubnetId
							}
						}

						$VpcId = $CECloud | Select-Object -ExpandProperty Subnets |
							Where-Object {$_.Name -ieq $SubnetId -or $_.Id -ieq $SubnetId} | 
							Select-Object -ExpandProperty NetworkId -ErrorAction SilentlyContinue

						# If we found the subnet, and we found the VPC, populate security groups
						# If it wasn't found, either the subnet provided was "Default" or not a recognized value
						# then we won't populate security groups since the only option is create new
						if (-not [System.String]::IsNullOrEmpty($VpcId))
						{
							#region SecurityGroups
							$SGSet = $CECloud | Select-Object -ExpandProperty SecurityGroups | 
								Where-Object {$_.NetworkId -ieq $VpcId} | 
								Select-Object -ExpandProperty SecurityGroupId
							$SGSet += [System.String]::Empty

							New-DynamicParameter -Name "ReplicatorSecurityGroupIDs" -Type ([System.String]) -ParameterSets @("AWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

							#endregion
						}

						break
					}
					"GCP" {
						# Do nothing
						break
					}
					"Azure" {
						# Do nothing
						break
					}
					default {
						throw "The cloud environment $($CECloud.Cloud) is not supported by this cmdlet yet."
					}
				}
			}

			return $RuntimeParameterDictionary
		}
	}

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.Collections.Hashtable]$SessSplat = @{
				"Session" = $Session
			}

			if ($ProjectId -ne [System.Guid]::Empty)
			{
				$SessSplat.Add("ProjectId", $ProjectId)
			}

			[System.Collections.Hashtable]$ExistingConfig = Get-CEReplicationConfiguration -Id $Id @SessSplat | ConvertTo-Hashtable

			# If a config hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Config")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Config = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the config object

							if ($Item.Key -ieq "ReplicationTags")
							{
								$Tags = @()
								# We need to convert the hashtable to the tag key/value structure
								$PSBoundParameters[$Item.Key].GetEnumerator() | ForEach-Object {
									$Tags += @{"key" = $_.Key; "value" = $_.Value}
								}

								$Config.Add("replicationTags", $Tags)
							}
							elseif ($Item.Key -ieq "SubnetId") 
							{
								[System.String]$SubnetId = $CECloud | 
									Select-Object -ExpandProperty Subnets | 
									Where-Object {$_.Name -ieq $PSBoundParameters["SubnetId"] -or $_.Id -ieq $PSBoundParameters["SubnetId"]} | 
									Select-Object -First 1 -ExpandProperty Id

								if (-not [System.String]::IsNullOrEmpty($SubnetId))
								{
									$Config.Add("subnetId", $SubnetId)
								}
							}
							else {
								$Config.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			# Merge the original and new blueprint
			[System.Collections.Hashtable]$NewConfig = Merge-HashTables -Source $ExistingConfig -Update $Config

			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replicationConfigurations/$($Id.ToString())"

			$ConfirmMessage = "Are you sure you want to update the replication configuration?"

			$WhatIfDescription = "Updated configuration to $(ConvertTo-Json -InputObject $NewConfig)"
			$ConfirmCaption = "Update Replication Configuration"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Sending updated config $(ConvertTo-Json -InputObject $NewConfig)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -Body (ConvertTo-Json -InputObject $NewConfig) -ContentType "application/json" -WebSession $SessionInfo.Session
	
				if ($Result.StatusCode -eq 200)
				{
					if ($PassThru) 
					{
						Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
					}
				}
				else
				{
					Write-Warning -Message "There was an issue updating the replication configuration: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Remove-CEReplicationConfiguration {
	<#
		.SYNOPSIS
			Removes a replication configuration. NOT YET SUPPORTED!

		.DESCRIPTION
			This cmdlet removes a specified replication configuration. NOT YET SUPPORTED!

		.PARAMETER Id
			The id of the replication configuration to remove.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			If specified, the deleted configuration is returned to the pipeline.

		.EXAMPLE
			Remove-CEReplicationConfiguration -Id 2ff58f32-cb82-4c41-accc-3001a104c560

			Removes the replication configuration with the provided Id.

		.INPUTS
			System.Guid

		.OUPUTS
			None or System.Management.Automation.PSCustomObject

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/22/2017
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid]$Id,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

		[Parameter()]
		[Switch]$PassThru
    )

    Begin {
		throw "Cmdlet not implemented."
    }

    Process {
        $SessionInfo = $null

		if (-not [System.String]::IsNullOrEmpty($Session)) {
			$SessionInfo = $script:Sessions.Get_Item($Session)
		}
		else {
			$SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
		}

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

            [System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replicationConfigurations"
            $Body = @{"id" = $Id.ToString()}

			$ConfirmMessage = "You are about to remove replication configuration $Id."
			$WhatIfDescription = "Removed replication configuration $Id"
			$ConfirmCaption = "Delete CE Replication Configuration"
			
			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Delete -Body (ConvertTo-Json -InputObject $Body) -WebSession $SessionInfo.Session
				Write-Verbose $Result.StatusCode
				Write-Verbose $Result.Content

				if ($PassThru)
				{
					Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
				}
			}
        }
        else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

#endregion

#region User

Function Get-CEUser {
	<#
        .SYNOPSIS
			Gets the current CloudEndure user information.

        .DESCRIPTION
			The cmdlet gets the current CloudEndure user information

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEUser

            Gets the current user information.

        .INPUTS
            None

        .OUTPUTS
           PSCustomObject

			This is a JSON representation of the returned value:
			{
			  "username": "user@example.com",
			  "account": "string",
			  "agentInstallationToken": "string",
			  "settings": {
				"sendNotifications": {
				  "projectIds": [
					"string"
				  ]
				}
			  },
			  "id": "string",
			  "selfLink": "string"
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/me"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the user info: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Set-CEConsolePassword {
	<#
		.SYNOPSIS
			Updates the password associated with the console logon.

		.DESCRIPTION
			The cmdlet updates the CE account password used to logon to the console.

		.PARAMETER OldPassword
			The current password for the account.

		.PARAMETER NewPassword
			The new password for the account. It must 8 characters or more, 1 upper, 1 lower, 1 numeric, and 1 special character.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Set-CEConsolePassword -OldPassword MyOldP@$$w0rd -NewPassword @$3cureP@$$w0rd
			
			The cmdlet updates the password.

		.INPUTS
			PSObject

		.OUTPUTS
			None

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$OldPassword,

		[Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$_ -ne $OldPassword
		})]
		[ValidatePattern("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{8,}")]
		[System.String]$NewPassword,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/changePassword"

			[System.Collections.Hashtable]$Body = @{
				"oldPassword" = $OldPassword;
				"newPassword" = $NewPassword
			}

			$ConfirmMessage = "Are you sure you want to update the console password?"
			$WhatIfDescription = "Updated password for $Session."
			$ConfirmCaption = "Update Console Password for $Session"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Sending updated config:`r`n $(ConvertTo-Json -InputObject $Body)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -Body (ConvertTo-Json -InputObject $Body) -ContentType "application/json" -WebSession $SessionInfo.Session

				if ($Result.StatusCode -eq 204)
				{
					Write-Verbose -Message "Password successfully updated."

					if ($PassThru)
					{
						Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
					}
				}
				else
				{
					Write-Warning -Message "There was an issue with changing the password: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Set-CEEmailNotifications {
	<#
        .SYNOPSIS
			Sets the email notification status.

        .DESCRIPTION
			The cmdlet either disables or enables email notifications.

		.PARAMETER Enabled
			Specifies that email notifications are enabled.

		.PARAMETER Disabled
			Specifies that email notifications are disabled.

		.PARAMETER ProjectId
			The project Id to enable or disable notifications for. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			Will pass through the updated user config to the pipeline.
            
        .EXAMPLE
            Set-CEEmailNotifications -Enabled

			Enables email notifications for the current user.

        .INPUTS
            None

        .OUTPUTS
           None

			This is a JSON representation of the returned value

			{
			  "username": "user@example.com",
			  "account": "string",
			  "agentInstallationToken": "string",
			  "settings": {
				"sendNotifications": {
				  "projectIds": [
					"string"
				  ]
				}
			  },
			  "id": "string",
			  "selfLink": "string"
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/7/2017
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Enabled")]
		[Switch]$Enabled,

		[Parameter(Mandatory = $true, ParameterSetName = "Disabled")]
		[Switch]$Disabled,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/users/$($SessionInfo.User.Id)"

			[System.String[]]$Ids = @()

			if ($Enabled) 
			{
				if ($ProjectId -eq [System.Guid]::Empty)
				{
					$ProjectId = $SessionInfo.ProjectId
				}

				$Ids += $ProjectId
			}

			[System.String]$Body = ConvertTo-Json -InputObject @{"id" = $SessionInfo.User.Id; "settings" = @{"sendNotifications" = @{"projectIds" = $Ids}}} -Depth 3

			Write-Verbose -Message "Setting email notifications update:`r`n$Body"
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200) 
			{
				if ($Enabled) 
				{
					Write-Verbose -Message "Email notifications enabled for $($SessionInfo.User.Username)."
				}
				else 
				{
					Write-Verbose -Message "Email notifications disabled for $($SessionInfo.User.Username)."
				}

				if ($PassThru)
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}
			else 
			{
				Write-Warning -Message "Email notifications could not be set properly, $($Result.StatusCode) - $($Result.StatusDescription) : $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

#endregion

#region Accounts

Function Get-CEAccount {
	<#
		.SYNOPSIS
			CloudEndure service account information.

		.DESCRIPTION
			CloudEndure service account information.

		.PARAMETER AccountId
			The account Id to retrieve information about. This defaults to the user account retrieved during login.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Get-CEAccount

			Gets the account data.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject

			This is a JSON representation of the returned object.
			{
			  "features": {
				"awsExtendedHDDTypes": true,
				"DRTier": true,
				"pit": true,
				"enableVolumeEncryption": true
			  },
			  "id": "string",
			  "ceAdminProperties": {
				"state": "ACTIVE",
				"version": "string"
			  }
			}

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	Param(
		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$AccountId = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($AccountId -eq [System.Guid]::Empty)
			{
				$AccountId = $SessionInfo.User.Account
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/accounts/$AccountId"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the CE account: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {

	}
}

Function Get-CEAccountSummary {
	<#
		.SYNOPSIS
			Retrieves summary data about the CE account.

		.DESCRIPTION
			This cmdlet retrieves a lot of information about the CE account including:

			-Account (Features & Id)
			-CloudCredentials (Id)
			-Clouds (Configured cloud environments)
			-DateTime (Current time)
			-License
			-Project
			-Regions (Source & Target)
			-ReplicationConfiguration
			-User

			This was the data originally returned by the celogin API call. The /ceme API is undocumented and this cmdlet may stop working without notice.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Get-CEAccountSummary

			Gets account summary data.

		.INPUTS
			None

		.OUTPUTS
			PSCustomObject

		 .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017

	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {
		Write-Warning -Message "The /ceme API is undocumented and this cmdlet may stop working without notice or return unexpected data."
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/ceme"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the account summary: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

#endregion

#region Licenses

Function Get-CELicense {
	<#
        .SYNOPSIS
           Gets the current state of license information.

        .DESCRIPTION
            The cmdlet lists the license information about the specified account.

		.PARAMETER Id
			The Id of the license to retrieve.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CELicense

            Retrieves the licenses in the account using the default session context.

        .INPUTS
            None

        .OUTPUTS
			System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			This is a JSON representation of the returned array:
			[
				{
				  "count": 0,
				  "durationFromStartOfUse": "string",
				  "used": 0,
				  "expirationDateTime": "2017-09-06T01:39:46Z",
				  "type": "MIGRATION",
				  "id": "string"
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Management.Automation.PSCustomObject[]])]
    Param(
		[Parameter(ValueFromPipeline = $true, ParameterSetName = "Get")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/licenses"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					if ($Id -ne [System.Guid]::Empty)
					{
						$Uri += "/$($Id.ToString())"
					}
					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				if ($Id -ne [System.Guid]::Empty)
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
				else 
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
				}
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the license information: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

#endregion

#region Project

Function Get-CEProject {
	<#
        .SYNOPSIS
			Gets basic information about the CE project.

        .DESCRIPTION
			The cmdlet retrieves basic information about the CE project in the CE account.

		.PARAMETER Id
			The Id of the project to retrieve.

		.PARAMETER Current
			Specified that information about the current project retrieved from the loging should be returned.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEProject

            Retrieves all projects up to 1500.

		.EXAMPLE
			Get-CEProject -Current
			
			Retrieves data about the current project.

        .INPUTS
            None or System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			This is a JSON representation of the returned array:
			[
				{
				  "source": "string",
				  "replicationConfiguration": "string",
				  "id": "string",
				  "name": "string",
				  "type": "MIGRATION"
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
		[Parameter(ParameterSetName = "Current")]
		[Switch]$Current,

		[Parameter(ValueFromPipeline = $true, Mandatory = "true", Position = 0, ParameterSetName = "Get")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					$Uri += "/$($Id.ToString())"

					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				"Current" {
					$Uri += "/$($SessionInfo.ProjectId)"
					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}
			
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				if ($PSCmdlet.ParameterSetName -ieq "List")
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)				
				}
				else 
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the project information: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Set-CEProject {
	<#
		.SYNOPSIS
			Configure project's source location, replication settings, etc.

		.DESCRIPTION
			Configure project's source location, replication settings, etc.

		.PARAMETER ProjectId
			The Id of the project to set. If this is not specified, the current project is used.

		.PARAMETER Config
			The config to update the project's settings.

		.PARAMETER Name
			The name of the project.
		
		.PARAMETER ReplicationConfiguration
			The Id of the replication configuration for the project to use.

		.PARAMETER Source
			The Name of the source cloud environment to use.

		.PARAMETER PassThru
			If specified, the updated configuration is returned to the pipeline.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Set-CEProject -Source "Generic"

			Sets the current project to use the source replication environment as "Generic".

		.INPUTS
			None or System.Collections.Hashtable

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject

			The JSON representation of the returned object:
			{
			  "source": "string",
			  "replicationConfiguration": "string",
			  "id": "string",
			  "name": "string",
			  "type": "MIGRATION"
			}
		
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([System.Management.Automation.PSCustomObject])]
	Param(
		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "Config", Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
		[System.Collections.Hashtable]$Config = @{},

		[Parameter(ParameterSetName = "Individual")]
		[System.String]$Name,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ReplicationConfiguration,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	DynamicParam {

		# Create the dictionary 
		$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		if ($Config -eq $null -or $Config -eq @{})
		{
			if (-not [System.String]::IsNullOrEmpty($Session)) {
				$DynSessionInfo = $script:Sessions.Get_Item($Session)
				$DynSession = $Session
			}
			else {
				$DynSessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
				$DynSession = $DynSessionInfo.User.Username
			}

			$DynSplat = @{
				"Session" = $DynSession
			}

			if ($ProjectId -ne $null -and $ProjectId -ne [System.Guid]::Empty)
			{
				$DynSplat.Add("ProjectId", $ProjectId)
			}

			New-DynamicParameter -Name "Source" -Type ([System.String]) -ValidateSet ((Get-CECloudRegion @DynSplat | Select-Object -ExpandProperty Name) + "Generic") -ParameterSets @("Individual") -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
		}

		return $RuntimeParameterDictionary
	}

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.Collections.Hashtable]$SessSplat = @{
				"Session" = $Session
			}

			if ($ProjectId -ne [System.Guid]::Empty)
			{
				$SessSplat.Add("ProjectId", $ProjectId)
			}

			[PSCustomObject[]]$CERegions = Get-CECloudRegion @SessSplat 

			# If a config hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Config")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Config = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the config object
							if ($Item.Key -ieq "Source")
							{
								$SourceId = (($CERegions | Select-Object Name,Id) + [PSCustomObject]@{"Name" = "Generic"; "Id" = $script:CloudIds["Generic"]}) | Where-Object {$_.Name -ieq $PSBoundParameters[$Item.Key]} | Select-Object -First 1 -ExpandProperty Id
								$Config.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $SourceId)
							}
							else 
							{
								$Config.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			if ($Config -ne $null -and $Config -ne @{} -and $Config.Count -gt 0)
			{			
				# We need the project to see the original source
				[System.Collections.Hashtable]$CurrentProject = Get-CEProject @SessSplat | ConvertTo-Hashtable

				# Build the confirmation messages with warnings about updates to source and destination
				$ConfirmMessage = "The action you are about to perform is destructive!"

				if (-not [System.String]::IsNullOrEmpty($Config["source"]))
				{        
					$OriginalSrc = $CurrentProject["source"]
					$OriginalSource = ($CERegions + [PSCustomObject]@{"Name" = "Generic"; "Id" = $script:CloudIds["Generic"]} ) | Where-Object {$_.Id -ieq $OriginalSrc } | Select-Object -First 1 -ExpandProperty Name
                    
					$ConfirmMessage += "`r`n`r`nChanging your Live Migration Source from $OriginalSource to $($PSBoundParameters["Source"]) will cause all current instances to be disconnected from CloudEndure: you will need to reinstall the CloudEndure Agent on all the instances and data replication will restart from zero."
				}

				if (-not [System.String]::IsNullOrEmpty($Config["replicationConfiguration"]))
				{
					$ConfirmMessage += "`r`n`r`nChanging your Live Migration Target replication configuration will cause all current instances to be disconnected from CloudEndure: you will need to reinstall the CloudEndure Agent on all the instances and data replication will restart from zero."
				}

				$WhatIfDescription = "Updated project configuration to $(ConvertTo-Json -InputObject $Config)"
				$ConfirmCaption = "Update Project Configuration"

				if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
				{
					if ($ProjectId -eq [System.Guid]::Empty)
					{
						$ProjectId = $SessionInfo.ProjectId
					}

					[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId"

					Write-Verbose -Message "Sending updated config`r`n$(ConvertTo-Json -InputObject $Config)"
					[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -Body (ConvertTo-Json -InputObject $Config) -ContentType "application/json" -WebSession $SessionInfo.Session
	
					if ($Result.StatusCode -eq 200)
					{
						if ($PassThru) 
						{
							Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
						}
					}
					else
					{
						Write-Warning -Message "There was an issue updating the project configuration: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
					}
				}
			}
			else
			{
				Write-Warning -Message "No updated configuration properties specified."
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

#endregion

#region Cloud Credentials

Function New-CECloudCredential {
	<#
		.SYNOPSIS
			Provide the credentials with which to access the cloud API.

		.DESCRIPTION
			Provide the credentials with which to access the cloud API.

		.PARAMETER Credential
			The credential conifguration to create.

			The configuration schema is as follows:
			{
			  "publicKey": "string",
			  "name": "string",
			  "cloudId": "string",
			  "privateKey": "string",
			  "accountIdentifier": "string"
			}

		.PARAMETER PublicKey
			AWS Only. The public part of the Cloud credentials.

		.PARAMETER Name
			An optional (can be empty), user provided, descriptive name.

		.PARAMETER CloudId
			The GUID Id of the cloud to create the credentials for.

		.PARAMETER PrivateKey,
			Cloud credentials secret. For AWS - The secret access key, For GCP - The private key in JSON format, For Azure - The certificate file.

		.PARAMETER AccountIdentifier.
			Azure & GCP Only. Cloud account identifier. For GCP - The project ID, For Azure - The subscription ID.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			If specified, the new cloud credential configuration is passed to the pipeline.

		.EXAMPLE
			New-CECloudCredential -PublicKey AKIA12341234 -CloudId AWS -PrivateKey asdfghhoitreq+ -Name "MyAWSCreds"

			Creates new AWS credentials for CE to use.

		.INPUTS
			None or System.Collections.Hashtable

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject
			
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(ParameterSetName = "Credential", ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Credential,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PublicKey,

		[Parameter(ParameterSetName = "Individual")]
		[System.String]$Name,

		[Parameter(Mandatory = $true, ParameterSetName = "Individual")]
		[ValidateSet("AWS", "Azure", "GCP", "On-Premises")]
		[System.String]$CloudId,

		[Parameter(Mandatory = $true, ParameterSetName = "Individual")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PrivateKey,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateNotNullOrEmpty()]
		[System.String]$AccountIdentifier,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		 $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($PSCmdlet.ParameterSetName -ne "Credential")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Credential = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the credential object

							if ($Item.Key -ieq "CloudId")
							{
								$Credential.Add("cloudId", $script:CloudIds[$PSBoundParameters[$Item.Key]])
							}
							elseif ($Item.Key -ieq "PrivateKey")
							{
								$Credential.Add("privateKey", $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PSBoundParameters[$Item.Key]))))
							}
							else
							{
								$Credential.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials"
			
			Write-Verbose -Message "New CE CloudCredentials:`r`n$(ConvertTo-Json -InputObject $Credential)"
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -Body (ConvertTo-Json -InputObject $Credential) -ContentType "application/json" -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 201)
			{
				if ($PassThru)
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}
			else
			{
				Write-Warning -Message "There was an issue creating the new cloud credentials: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Set-CECloudCredential {
	<#
		.SYNOPSIS
			Updates cloud credentials for CE to use in the target environment.

		.DESCRIPTION
			This cmdlet updates credentials that CloudEndure will utilize to launch resources in the target environment.

		.PARAMETER Credential
			The credential conifguration to create.

			The configuration schema is as follows:
			{
			  "publicKey": "string",
			  "name": "string",
			  "cloudId": "string",
			  "privateKey": "string",
			  "accountIdentifier": "string"
			}

		.PARAMETER PublicKey
			AWS Only. The public part of the Cloud credentials.

		.PARAMETER Name
			An optional (can be empty), user provided, descriptive name.

		.PARAMETER CloudId
			The GUID Id of the cloud to create the credentials for. If this is not specified, the current cloud is used.

		.PARAMETER PrivateKey,
			Cloud credentials secret. For AWS - The secret access key, For GCP - The private key in JSON format, For Azure - The certificate file.

		.PARAMETER AccountIdentifier.
			Azure & GCP Only. Cloud account identifier. For GCP - The project ID, For Azure - The subscription ID.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			If specified, the updated cloud credential configuration is passed to the pipeline.

		.EXAMPLE 
			Set-CECloudCredential -PublicKey AKIAPUTJUST34HYMMDRE -PrivateKey g3t89hLRcAhhq67KB8LNdx2C+9twO49uvajFF1Wa -Name "UpdatedAWSCreds"

			This sets new credentials for the current CE account.

		.INPUTS
			None

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject

			The JSON representation of the returned object:
			{
			  "id": "string",
			  "publicKey": "string",
			  "accountIdentifier": "string",
			  "cloud": "string",
			  "name": "string"
			}
			
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
	Param(
		# This Id can be an empty GUID for on-premises
		[Parameter()]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "Credential", ValueFromPipeline = $true, Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Credential,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PublicKey,

		[Parameter(ParameterSetName = "Individual")]
		[System.String]$Name,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateSet("AWS", "Azure", "GCP", "On-Premises")]
		[System.String]$CloudId,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateNotNullOrEmpty()]
		[System.String]$PrivateKey,

		[Parameter(ParameterSetName = "Individual")]
		[ValidateNotNullOrEmpty()]
		[System.String]$AccountIdentifier,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if (-not $PSBoundParameters.ContainsKey("Id"))
			{
				$Id = $SessionInfo.CloudCredentials
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$Id"

			if ($PSCmdlet.ParameterSetName -ine "Credential")
			{
				# Convert only the non-common parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Key)})
                {
					[System.String[]]$Sets = $Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key
                    $Params.Add($Item.Key, $Sets)
                }

                $RuntimeParameterDictionary.GetEnumerator() | Where-Object {-not $script:CommonParams.Contains($_.Name)} | ForEach-Object {
                    [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                    if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                    {
						[System.String[]]$ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
						$Params.Add($Param.Name, $ParameterSets)
                    }
                }

				$Credential = @{}

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set or is a parameter only part of __AllParameterSets
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName) -or ($Item.Value.Length -eq 1 -and $Item.Value.Contains($script:AllParameterSets)))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the credential object

							if ($Item.Key -ieq "CloudId")
							{
								$Credential.Add("cloudId", $script:CloudIds[$PSBoundParameters[$Item.Key]])
							}
							elseif ($Item.Key -ieq "PrivateKey")
							{
								$Credential.Add("privateKey", $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PSBoundParameters[$Item.Key]))))
							}
							else
							{
								$Credential.Add($Item.Key.Substring(0, 1).ToLower() + $Item.Key.Substring(1), $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			if (-not $Credential.ContainsKey("cloudId"))
			{
				[System.Collections.Hashtable]$SessSplat = @{
					"Session" = $Session
				}

				$CurrentCreds = Get-CECloudCredential -Current @SessSplat
				$Credential.Add("cloudId", $CurrentCreds.Cloud)
			}

			$ConfirmMessage = "Are you sure you want to update the cloud credentials?"
			$WhatIfDescription = "Updated credentials."
			$ConfirmCaption = "Update CE Credentials"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Sending updated config:`r`n $(ConvertTo-Json -InputObject $Credential)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -Body (ConvertTo-Json -InputObject $Credential) -ContentType "application/json" -WebSession $SessionInfo.Session

				if ($Result.StatusCode -eq 200)
				{
					Write-Verbose -Message "Successfully updated cloud credentials."

					if ($PassThru)
					{
						Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
					}
				}
				else
				{
					Write-Warning -Message "There was an issue updating the cloud credentials: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Get-CECloudCredential {
	<#
        .SYNOPSIS
			Returns information about cloudCredentials in the account.

        .DESCRIPTION
            This cmdlet returns information about cloudCredentials in the account. If an Id is specified, the information specific to that Id is returned, otherwise the credentials are listed.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CECloudCredential -Current

            Retrieves the cloud credentials associated with the current account.

		.EXAMPLE 
			Get-CECloudCredential -Id 9f620e77-3f2e-4df3-bc37-ec4ee736d92f

			Get the cloud credential associated with the provided Id.

		.EXAMPLE
			Get-CECloudCredential -Limit 10
		
			Retrieves the first 10 cloud credentials in the current account.

        .INPUTS
            None or System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Management.Automation.PSCustomObject[]])]
    Param(
		# This parameter can be specified as the empty GUID for on-premises
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = "Get")]
		[System.Guid]$Id,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter(ParameterSetName = "Current")]
		[Switch]$Current,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					$Uri += "/$($Id.ToString())"

					break
				}
				"Current" {
					$Id = $SessionInfo.CloudCredentials
					$Uri += "/$($Id.ToString())"

					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				if ($PSCmdlet.ParameterSetName -ieq "List")
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
				}
				else
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}
			else
			{
				Write-Warning -Message "There was an issue getting the cloud credentials: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

#endregion

#region Cloud

Function Get-CECloud {
	<#
		.SYNOPSIS
			Gets information about the available clouds to use with CloudEndure

        .DESCRIPTION
			The cmdlet retrieves information about a cloud or lists the available clouds if no Id is specified.

		.PARAMETER Id
			The Id of the region to retrieve. If no Id is specified, all available regions in the target cloud are returned.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Get-CECloud

			Retrieves all of the available clouds.

		.EXAMPLE
			Get-CECloud -Id 4c7b3582-9e73-4866-858a-8e1ac6e818b3

			Retrieves informatio about the cloud with the specified Id, which is AWS.

		.INPUTS
			None or System.Guid

		.OUPUTS
			System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			This is a JSON representation of the return array:
			[
				{
				  "id": "string",
				  "roles": [
					"SOURCE"
				  ],
				  "name": "AWS"
				}
			]
			
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
	#>
	[CmdletBinding(DefaultParameterSetName = "List")]
	[OutputType([System.Management.Automation.PSCustomObject], [System.Management.Automation.PSCustomObject[]])]
	Param (
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = "Get")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/clouds"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					# This REST API doesn't support supplying the Id as part of the URL

					$Offset = 0
					$Limit = 1500

					[System.UInt32]$Count = $Limit
					[System.Int32]$ResultCount = 0
					[System.Boolean]$Found = $false
					$Cloud = $null

					# Go until the results returned are less than the specified limit or the loop
					# breaks when the config is found
					while ($Count -ge $ResultCount)
					{
						Write-Verbose -Message "Querying clouds from $Offset to $($Offset + $Limit)."

						[System.String]$QueryString = "?offset=$Offset&limit=$Limit"
						[System.String]$TempUri = "$Uri$QueryString"
						[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $TempUri -Method Get -WebSession $SessionInfo.Session

						if ($Result.StatusCode -eq 200)
						{
							[PSCustomObject[]]$Content = ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
							$ResultCount = $Content.Length

							$Cloud = $Content | Where-Object {$_.Id -ieq $Id.ToString()}

							if ($Cloud -ne $null)
							{
								Write-Output -InputObject ([PSCustomObject]($Cloud | Select-Object -First 1))
								$Found = $true
								break
							}
							else
							{
								$Offset += $Limit
							}
						}
						else
						{
							Write-Warning -Message "There was an issue retrieving CE clouds: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
							break
						}

					}

					if (-not $Found)
					{
						throw "The cloud with Id $Id was not found."
					}

					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}
			
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($PSCmdlet.ParameterSetName -ieq "List")
			{
				Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)				
			}
			else 
			{
				Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content) | Where-Object {$_.Id -ieq $Id} | Select-Object -First 1)
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Get-CECloudRegion {
	<#
        .SYNOPSIS
			Gets information about the available destination cloud regions.

        .DESCRIPTION
			The cmdlet retrieves information about a region in the target cloud or if no Id is specified, all available regions in the target cloud. 
			This information includes the available regions, their subnets, security groups, IAM instance profiles, available instance types, and KMS keys.

		.PARAMETER Id
			The Id of the region to retrieve. If no Id is specified, all available regions in the target cloud are returned.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

		.PARAMETER Current
			Gets the region information about the current target region.

		.PARAMETER Target
			Gets the region information about the current target region.

		.PARAMETER CloudCredentials
			UUID of the credentials to use. In case of on-premise, you should use the null UUID "00000000-0000-0000-0000-000000000000". If this is not specified, it defaults to the cloud credentials acquired at logon.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CECloudRegion

            Retrieves the details of all regions the destination cloud environment.

		.EXAMPLE
			Get-CECloudRegion -Id 47d842b8-ebfa-4695-90f8-fb9ab686c708

			Retrieves details of the region identified with the supplied Guid.

		.EXAMPLE
			Get-CECloudRegion -Current
			
			Retrieves details about the current target region.

        .INPUTS
            System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			This is a JSON representation of the output array:
			[		
				{
				  "subnets": [
					{
					  "subnetId": "string",
					  "networkId": "string",
					  "name": "string"
					}
				  ],
				  "placementGroups": [
					"string"
				  ],
				  "name": "string",
				  "instanceTypes": [
					"string"
				  ],
				  "iamRoles": [
					"string"
				  ],
				  "id": "string",
				  "volumeEncryptionKeys": [
					"string"
				  ],
				  "securityGroups": [
					{
					  "networkId": "string",
					  "securityGroupId": "string",
					  "name": "string"
					}
				  ],
				  "staticIps": [
					"string"
				  ],
				  "cloud": "string"
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
    #>
	[CmdletBinding(DefaultParameterSetName = "List")]
	[OutputType([PSCustomObject], [PSCustomObject[]])]
	Param(
		[Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = "Get")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter(ParameterSetName = "GetTarget")]
		[Alias("Target")]
		[Switch]$Current,

		[Parameter(ParameterSetName = "GetSource")]
		[Switch]$Source,

		[Parameter()]
		[System.Guid]$CloudCredentials = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {

	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			# Check to see if they were specified since an empty GUID means on-premises
			if (-not $PSBoundParameters.ContainsKey("CloudCredentials"))
			{
				$CloudCredentials = $SessionInfo.CloudCredentials
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$CloudCredentials/regions"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					$Uri += "/$($Id.ToString())"

					break
				}
				"GetTarget" {					
					$Id = $SessionInfo.Regions.Target.Id
					$Uri += "/$($Id.ToString())"

					break
				}
				"GetSource" {
					$Id = $SessionInfo.Regions.Source.Id

					if ($Id -ne $SessionInfo.Regions.Generic.Id)
					{
						$Uri += "/$($Id.ToString())"
					}
					else 
					{
						return $SessionInfo.Regions.Generic
					}

					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				if ($PSCmdlet.ParameterSetName -ieq "List")
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
				}
				else 
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}
			else
			{
				Write-Warning -Message "There was an issue getting the CE cloud region(s): $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Get-CETargetCloud {
	<#
        .SYNOPSIS
			Gets information about the destination cloud environment.

        .DESCRIPTION
			The cmdlet retrieves information about the target/destination cloud environment.

		.PARAMETER CloudCredentials
			UUID of the credentials to use. In case of on-premise, you should use the null UUID "00000000-0000-0000-0000-000000000000". If this is not specified, it defaults to the cloud credentials acquired at logon.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CETargetCloud

            Retrieves the details of the destination cloud environment.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
    #>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	Param(
		[Parameter()]
		[System.Guid]$CloudCredentials = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {

	}

	Process {
		$Splat = @{}

		if (-not [System.String]::IsNullOrEmpty($Session))
		{
			$Splat.Add("Session", $Session)
		}

		if ($PSBoundParameters.ContainsKey("CloudCredentials"))
		{
			$Splat.Add("CloudCredentials", $CloudCredentials)
		}

		Write-Output -InputObject (Get-CECloudRegion -Current @Splat)
	}

	End {
	}
}

Function Get-CESourceCloud {
	<#
        .SYNOPSIS
			Gets information about the source cloud environment.

        .DESCRIPTION
			The cmdlet retrieves information about the source cloud environment.

		.PARAMETER CloudCredentials
			UUID of the credentials to use. In case of on-premise, you should use the null UUID "00000000-0000-0000-0000-000000000000". If this is not specified, it defaults to the cloud credentials acquired at logon.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CESourceCloud

            Retrieves the details of the source cloud environment.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/28/2017
    #>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	Param(
		[Parameter()]
		[System.Guid]$CloudCredentials = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {

	}

	Process {
		$Splat = @{}

		if (-not [System.String]::IsNullOrEmpty($Session))
		{
			$Splat.Add("Session", $Session)
		}

		if ($PSBoundParameters.ContainsKey("CloudCredentials"))
		{
			$Splat.Add("CloudCredentials", $CloudCredentials)
		}

		Write-Output -InputObject (Get-CECloudRegion -Source @Splat)
	}

	End {
	}
}

#endregion

#region Machines

Function Get-CEMachine {
     <#
        .SYNOPSIS
           Gets a list of CE machines in an account or a specific CE machine.

        .DESCRIPTION
            The cmdlet lists all of the CE machines in the account if no Id is provided. If an Id is provided, then that specific machine is fetched.

		.PARAMETER Id
			The Id of the instance to get. If this is not specified, all instances are returned.

		.PARAMETER Offset
			With which item to start (0 based).

		.PARAMETER Limit
			A number specifying how many entries to return between 0 and 1500 (defaults to 1500).

		.PARAMETER IgnoreMachineStatus
			Returns all machines in the project regardless of replications status.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEMachine

            Lists all of the CE machines in the account.

		.EXAMPLE
			Get-CEMachine -Id 9f620e77-3f2e-4df3-bc37-ec4ee736d92f

			Gets details for the machine specified.

        .INPUTS
            None or System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			This is a JSON representation of the returned array:
			[
				{
				  "sourceProperties": {
					"name": "string",
					"disks": [
					  {
						"isProtected": true,
						"name": "string",
						"size": 0
					  }
					],
					"machineCloudState": "string",
					"publicIps": [
					  "string"
					],
					"memory": 0,
					"os": "string",
					"cpu": [
					  {
						"cores": 0,
						"modelName": "string"
					  }
					],
					"machineCloudId": "string"
				  },
				  "replicationInfo": {
					"lastConsistencyDateTime": "2017-09-10T14:19:39Z",
					"nextConsistencyEstimatedDateTime": "2017-09-10T14:19:39Z",
					"rescannedStorageBytes": 0,
					"backloggedStorageBytes": 0,
					"initiationStates": {
					  "items": [
						{
						  "steps": [
							{
							  "status": "NOT_STARTED",
							  "message": "string",
							  "name": "WAITING_TO_INITIATE_REPLICATION"
							}
						  ],
						  "startDateTime": "2017-09-10T14:19:39Z"
						}
					  ],
					  "estimatedNextAttemptDateTime": "2017-09-10T14:19:39Z"
					},
					"replicatedStorageBytes": 0,
					"totalStorageBytes": 0
				  },
				  "license": {
					"startOfUseDateTime": "2017-09-10T14:19:39Z",
					"licenseId": "string"
				  },
				  "id": "string",
				  "replicationStatus": "STOPPED",
				  "replica": "string",
				  "lifeCycle": {
					"failoverDateTime": "2017-09-10T14:19:39Z",
					"cutoverDateTime": "2017-09-10T14:19:39Z",
					"lastTestDateTime": "2017-09-10T14:19:39Z",
					"connectionEstablishedDateTime": "2017-09-10T14:19:39Z",
					"agentInstallationDateTime": "2017-09-10T14:19:39Z"
				  },
				  "isAgentInstalled": true
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "List")]
	[OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "Get", Mandatory = $true)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid]$Id = [System.Guid]::Empty,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, [System.UInt32]::MaxValue)]
		[System.UInt32]$Offset = 0,

		[Parameter(ParameterSetName = "List")]
		[ValidateRange(0, 1500)]
		[System.UInt32]$Limit = 1500,

		[Parameter(ParameterSetName = "List")]
		[Switch]$IgnoreMachineStatus,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/machines"

			switch ($PSCmdlet.ParameterSetName)
			{
				"Get" {
					$Uri += "/$($Id.ToString())"

					break
				}
				"List" {
					if ($Offset -gt 0 -or $Limit -lt 1500)
					{
						$QueryString = [System.String]::Empty

						if ($Offset -gt 0)
						{
							$QueryString += "&offset=$Offset"
						}

						if ($Limit -lt 1500)
						{
							$QueryString += "&limit=$Limit"
						}

						if ($IgnoreMachineStatus)
						{
							$QueryString += "&all=true"
						}

						# Remove the first character which is an unecessary ampersand
						$Uri += "?$($QueryString.Substring(1))"
					}
					break
				}
				default {
					Write-Warning -Message "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				$Temp = ConvertFrom-Json -InputObject $Result.Content

				if ($PSCmdlet.ParameterSetName -ieq "List") 
				{
					Write-Output -InputObject $Temp.Items
				}
				else 
				{
					Write-Output -InputObject $Temp
				}
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving CE machines: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}	
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Remove-CEMachine {
	<#
        .SYNOPSIS
           Removes a machine from CloudEndure and initiates an uninstall of the agent on the source machine.

        .DESCRIPTION
            The cmdlet uninstalls the CloudEndure agent on the source instance, causes data replication to stop, and the instance will no longer appear in the CloudEndure Console.

			All cloud artifacts associated with those machines with the exception of launched target machines are deleted.

		.PARAMETER Ids
			The Ids of the instances to remove from CloudEndure.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Remove-CEMachine -Ids e0dc06ba-86b5-4c4c-b25b-20a68089c797 -Force

            Removes the CE instance with the specified Id and bypasses the confirm dialog.

		.EXAMPLE
            Remove-CEMachine -Ids @(e0dc06ba-86b5-4c4c-b25b-20a68089c797, b1df0696-8da5-4648-b2cc-222aa89c800) -Force

            Removes the CE instancea with the specified Ids and bypasses the confirm dialog.

        .INPUTS
            System.Guid[]

        .OUTPUTS
           None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
	[OutputType()]
    Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/machines"

			[System.String]$Body = ConvertTo-Json -InputObject @{"machineIDs" = $Ids}

			$ConfirmMessage = @"
You are about to uninstall the CloudEndure Agent from $($Ids.Length) Source instance$(if ($Ids.Length -gt 1) { "s" }).

This will cause data replication to stop and the instance$(if ($Ids.Length -gt 1) { "s" }) will no longer appear in the CloudEndure Console.
"@

			$WhatIfDescription = "Deleted CE Instances $([System.String]::Join(",", $Ids))"
			$ConfirmCaption = "Delete CE Instance $([System.String]::Join(",", $Ids))"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Delete -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session
        
				if ($Result.StatusCode -eq 204)
				{
					Write-Verbose -Message "Machine(s) $([System.String]::Join(",", $Ids)) successfully deleted."
				}
				else
				{
					Write-Warning -Message "There was an issue removing the CE machines: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Get-CEMachineReplica {
	<#
		.SYNOPSIS
			Gets a target machine details.

		.DESCRIPTION
			This cmdlet retrieves information about a target replica instance. If the id is not found, a 404 response is returned.

		.PARAMETER Id
			The Id of the replica instance to get.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Get-CEMachineReplica -Id cc7ba582-9e83-4866-858a-8e1ac6e818b4

			Gets the replica instance specified by the provided Id.

		.INPUTS
			System.Guid

		.OUPUTS
			System.Management.Automation.PSCustomObject

			This is a JSON representation of the return value:
			{
			  "machine": "string",
			  "cloudEndureCreationDateTime": "2017-09-10T14:19:39Z",
			  "name": "string",
			  "pointInTime": "string",
			  "machineCloudState": "string",
			  "publicIps": [
				"string"
			  ],
			  "regionId": "string",
			  "id": "string",
			  "machineCloudId": "string"
			}

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	Param(		
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid]$Id,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replicas/$($Id.ToString())"
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
			}
			else
			{
				Write-Warning -Message "There was an issue getting the replica instance data: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

#endregion

#region Actions

Function New-CEInstallationToken {
	<#
        .SYNOPSIS
			Replaces the current installation token with a new one.

        .DESCRIPTION
			The cmdlet creates a new installation token and invalidates the old one.

		.PARAMETER PassThru
			If specified, the new installation token will be returned to the pipeline.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            $Token = New-CEInstallationToken -PassThru

            Invalidates the old installation token and creates a new one, which is passed back to the pipeline.

        .INPUTS
            None

        .OUTPUTS
           None or System.String

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/10/2017
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replaceAgentInstallationToken"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				Write-Verbose -Message "Successfully replaced token."
				
				if ($PassThru) 
				{
					Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content).AgentInstallationToken
				}
			}
			else
			{
				Write-Warning -Message "There was an issue replacing the installation token: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Get-CEInstallationToken {
	<#
        .SYNOPSIS
			Gets the current installation token.

        .DESCRIPTION
			The cmdlet gets the current installation token.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            $Token = Get-CEInstallationToken

            Gets the current installation token.

        .INPUTS
            None

        .OUTPUTS
           System.String

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/me"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200)
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content).AgentInstallationToken
			}
			else
			{
				Write-Warning -Message "There was an issue retrieving the agent installation token: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Start-CEDataReplication {
	<#
        .SYNOPSIS
           Starts data replication for specified instances.

        .DESCRIPTION
            The cmdlet starts data replication for specified instances. 

			If invalid IDs are provided, they are ignored and identified in the return data.
			
		.PARAMETER Ids
			The Ids of the instances to start replication for.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER PassThru
			If specified, the cmdlet will return updated instance information as well as a list of invalid IDs.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Start-CEReplication -Ids e0dc06ba-86b5-4c4c-b25b-20a68089c797 -Force

            Starts replication for the specified instance.

        .INPUTS
            System.Guid[]

        .OUTPUTS
           PSCustomObject

			This is a JSON representation of the returned data:
			{
			  "items": [
				{
				  "sourceProperties": {
					"name": "string",
					"disks": [
					  {
						"isProtected": true,
						"name": "string",
						"size": 0
					  }
					],
					"machineCloudState": "string",
					"publicIps": [
					  "string"
					],
					"memory": 0,
					"os": "string",
					"cpu": [
					  {
						"cores": 0,
						"modelName": "string"
					  }
					],
					"machineCloudId": "string"
				  },
				  "replicationInfo": {
					"lastConsistencyDateTime": "2017-09-10T14:19:39Z",
					"nextConsistencyEstimatedDateTime": "2017-09-10T14:19:39Z",
					"rescannedStorageBytes": 0,
					"backloggedStorageBytes": 0,
					"initiationStates": {
					  "items": [
						{
						  "steps": [
							{
							  "status": "NOT_STARTED",
							  "message": "string",
							  "name": "WAITING_TO_INITIATE_REPLICATION"
							}
						  ],
						  "startDateTime": "2017-09-10T14:19:39Z"
						}
					  ],
					  "estimatedNextAttemptDateTime": "2017-09-10T14:19:39Z"
					},
					"replicatedStorageBytes": 0,
					"totalStorageBytes": 0
				  },
				  "license": {
					"startOfUseDateTime": "2017-09-10T14:19:39Z",
					"licenseId": "string"
				  },
				  "id": "string",
				  "replicationStatus": "STOPPED",
				  "replica": "string",
				  "lifeCycle": {
					"failoverDateTime": "2017-09-10T14:19:39Z",
					"cutoverDateTime": "2017-09-10T14:19:39Z",
					"lastTestDateTime": "2017-09-10T14:19:39Z",
					"connectionEstablishedDateTime": "2017-09-10T14:19:39Z",
					"agentInstallationDateTime": "2017-09-10T14:19:39Z"
				  },
				  "isAgentInstalled": true
				}
			  ],
			  "invalidMachineIDs": [
				"string"
			  ]
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
	[OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			[System.Collections.Hashtable]$SessSplat = @{
				"Session" = $Session
			}

			if ($ProjectId -ne [System.Guid]::Empty)
			{
				$SessSplat.Add("ProjectId", $ProjectId)
			}

			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/startReplication"

			[System.String]$Body = ConvertTo-Json -InputObject @{"machineIDs" = $Ids}

			$Target = Get-CETargetCloud @SessSplat | Select-Object -ExpandProperty Cloud

			$ConfirmMessage = @"
Are you sure you want to start data replication?

If you continue, you will begin to incur additional costs from $Target for data transfer, storage, compute and other resources.

(selected instances for which data replication is already started will not be affected)
"@

			$WhatIfDescription = "Started replication for CE Instances $([System.String]::Join(",", $Ids))"
			$ConfirmCaption = "Start Data Replication for $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Requesting replication for:`r`n$Body"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session

				if ($Result.StatusCode -eq 200)
				{
					[PSCustomObject]$Temp = ConvertFrom-Json -InputObject $Result.Content

					if ($Temp.Items -ne $null -and $Temp.Items.Length -gt 0)
					{
						Write-Verbose -Message "Replication successfully stopped for machine(s) $([System.String]::Join(",", $($Result | Select-Object -ExpandProperty Items | Select-Object -ExpandProperty Id)))."

						if ($PassThru)
						{
							Write-Output -InputObject $Temp
						}
					}
					else
					{
						Write-Warning -Message "No items were returned for successful replication stop."
					}

					if ($Temp.InvalidMachineIDs -ne $null -and $Temp.InvalidMachineIDs.Length -gt 0)
					{
						Write-Warning -Message "The following ids were invalid: $([System.String]::Join(",", ($Temp | Select-Object -ExpandProperty InvalidMachineIDs)))" 
					}					
				}
				else
				{
					Write-Warning -Message "There was an issue starting replication: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Stop-CEDataReplication {
	<#
        .SYNOPSIS
           Stops data replication for specified instances.

        .DESCRIPTION
            The cmdlet stops data replication for specified instances. The instances will remain in the console, and replication can be started from zero again.

			If invalid IDs are provided, they are ignored and identified in the return data.

		.PARAMETER Ids
			The Ids of the instances to stop replication on.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER PassThru
			If specified, the cmdlet will return updated instance information as well as a list of invalid IDs.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Stop-CEReplication -Ids e0dc06ba-86b5-4c4c-b25b-20a68089c797 -Force

            Stops replication for the specified instance.

        .INPUTS
            System.Guid[]

        .OUTPUTS
			None or PSCustomObject

			This is a JSON representation of the returned data:
			{
				"items": [
				{
				  "sourceProperties": {
					"name": "string",
					"disks": [
					  {
						"isProtected": true,
						"name": "string",
						"size": 0
					  }
					],
					"machineCloudState": "string",
					"publicIps": [
					  "string"
					],
					"memory": 0,
					"os": "string",
					"cpu": [
					  {
						"cores": 0,
						"modelName": "string"
					  }
					],
					"machineCloudId": "string"
				  },
				  "replicationInfo": {
					"lastConsistencyDateTime": "2017-09-10T14:19:39Z",
					"nextConsistencyEstimatedDateTime": "2017-09-10T14:19:39Z",
					"rescannedStorageBytes": 0,
					"backloggedStorageBytes": 0,
					"initiationStates": {
					  "items": [
						{
						  "steps": [
							{
							  "status": "NOT_STARTED",
							  "message": "string",
							  "name": "WAITING_TO_INITIATE_REPLICATION"
							}
						  ],
						  "startDateTime": "2017-09-10T14:19:39Z"
						}
					  ],
					  "estimatedNextAttemptDateTime": "2017-09-10T14:19:39Z"
					},
					"replicatedStorageBytes": 0,
					"totalStorageBytes": 0
				  },
				  "license": {
					"startOfUseDateTime": "2017-09-10T14:19:39Z",
					"licenseId": "string"
				  },
				  "id": "string",
				  "replicationStatus": "STOPPED",
				  "replica": "string",
				  "lifeCycle": {
					"failoverDateTime": "2017-09-10T14:19:39Z",
					"cutoverDateTime": "2017-09-10T14:19:39Z",
					"lastTestDateTime": "2017-09-10T14:19:39Z",
					"connectionEstablishedDateTime": "2017-09-10T14:19:39Z",
					"agentInstallationDateTime": "2017-09-10T14:19:39Z"
				  },
				  "isAgentInstalled": true
				}
			  ],
			  "invalidMachineIDs" : [
				"string"
			  ]
			}

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
	[OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/stopReplication"

			[System.String]$Body = ConvertTo-Json -InputObject @{"machineIDs" = $Ids}

			$ConfirmMessage = @"
Are you sure you want to stop data replication?

If you continue, all replicated data for $(if ($Ids.Length -gt 1) { "these instances" } else { "this instance" }) will be purged and you will no longer be able to launch Target instances for either testing purposes or for Cutover.

$(if ($Ids.Length -gt 1) { "These instances" } else { "This instance" }) will still appear in this Console and you will be able to restart data replication for $(if ($Ids.Length -gt 1) { "them" } else { "it" }) whenever you wish, however data replication will then begin from zero.

(selected instances for which data replication is already stopped will not be affected)
"@

			$WhatIfDescription = "Stopped replication for CE Instances $([System.String]::Join(",", $Ids))"
			$ConfirmCaption = "Stop Data Replication for $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Requesting to stop replication for:`r`n$Body"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session
        
				if ($Result.StatusCode -eq 200)
				{
					[PSCustomObject]$Temp = ConvertFrom-Json -InputObject $Result.Content

					if ($Temp.Items -ne $null -and $Temp.Items.Length -gt 0)
					{
						Write-Verbose -Message "Replication successfully stopped for machine(s) $([System.String]::Join(",", ($Temp | Select-Object -ExpandProperty Items | Select-Object -ExpandProperty Id)))."

						if ($PassThru)
						{
							Write-Output -InputObject $Temp
						}
					}
					else
					{
						Write-Warning -Message "No items were returned for successfull replication stop."
					}

					if ($Temp.InvalidMachineIDs -ne $null -and $Temp.InvalidMachineIDs.Length -gt 0)
					{
						Write-Warning -Message "The following ids were invalid: $([System.String]::Join(",", ($Temp | Select-Object -ExpandProperty InvalidMachineIDs)))" 
					}
				}
				else
				{
					Write-Warning -Message "There was an issue stopping replication: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}				
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Invoke-CEMachineFailover {
	<#
		.SYNOPSIS
			Spawns a failover job to fail over the specified source machines (Applicable in DR projects only). The source and target locations of the project are reversed: The launched target machines become the new replication source machines, the CloudEndure agent is removed from the previous source machines.

		.DESCRIPTION
			Spawns a failover job to fail over the specified source machines (Applicable in DR projects only). The source and target locations of the project are reversed: The launched target machines become the new replication source machines, the CloudEndure agent is removed from the previous source machines.

		.PARAMETER Ids
			The Ids of the instances to failover. The most recent point in time is used for each.

		.PARAMETER PointInTime
			An array of hashtables specifying the machine Id and Point In Time Id to failover. For example, 

			-PointInTime @(@{"machineId" = "guid"; "pointInTimeId" = "guid" }, @{"machineId" = "guid2"})

			In this case, the first machine uses the specified pointInTimeId, while the second machine uses the latest pointInTime since that property was omitted.

		.PARAMETER UseExistingMachines
			Specify to use only all machines with replicas.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER PassThru
			If specified, the cmdlet will return job information about the failover.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE 
			Invoke-CEMachineFailover -UseExistingMachines -Force

			Invokes a failover for all CE machines with an active replica.

		.EXAMPLE
			Invoke-CEMachineFailover -Ids @(e0dc06ba-86b5-4c4c-b25b-20a68089c797)

			Invokes a failover for the specific instance using the latest point in time.

		.EXAMPLE
			Invoke-CEMachineFailover -PointInTime @(@{"machineId" = "e0dc06ba-86b5-4c4c-b25b-20a68089c797"; "pointInTimeId" = "f1ed17cb-46a3-4dd8-525e-67770123aaef"})

		.INPUTS
			None or System.Guid[]

		.OUTPUTS
			System.Management.Automation.PSCustomObject

			This is a JSON representation of the returned value:
			{
			  "status": "PENDING",
			  "type": "TEST",
			  "id": "string",
			  "log": [
				{
				  "message": "string",
				  "logDateTime": "2017-09-10T14:19:39Z"
				}
			  ]
			}

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH", DefaultParameterSetName = "Latest")]
	[OutputType([System.Management.Automation.PSCustomObject])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Latest", Position = 0)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid[]]$Ids = @(),

		[Parameter(Mandatory = $true, ParameterSetName = "PointInTime", Position = 0)]
		[ValidateNotNull()]
		[System.Collections.Hashtable[]]$PointInTime = @(),

		[Parameter(ParameterSetName = "Existing")]
		[Switch]$UseExistingMachines,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}

	Process {
		$SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session.ToLower())
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/performFailover"

			$Items = @()

			switch ($PSCmdlet.ParameterSetName)
			{
				"Latest" {
					foreach ($Item in $Ids)
					{
						$Items += @{"machineId" = $Item}
					}

					$Uri += "?useExistingMachines=false"

					break
				}
				"PointInTime" {

					foreach ($Item in $PointInTime)
					{
						[System.Collections.Hashtable]$Machine = @{}

						if ($Item.ContainsKey("machineId"))
						{
							 $Machine.Add("machineId", $Item["machineId"])

							if ($Item.ContainsKey("pointInTimeId"))
							{
								$Machine.Add("pointInTimeId", $Item["pointInTimeId"])
							}

							$Items += $Machine
						}
						else
						{
							throw "The PointInTime array contained an item without a machineId property, this is required for each object."
						}
					}

					$Uri += "?useExistingMachines=false"

					break
				}
				"Existing" {
					$Uri += "?useExistingMachines=true"
					break
				}
				default {
					throw "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}

			$ConfirmMessage = @"
Are you sure you want to perform a failover?
"@

			$WhatIfDescription = "Performed a failover for CE Instances."
			$ConfirmCaption = "Perform CE Failover."

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[System.Collections.Hashtable]$Splat = @{}

				if ($PSCmdlet.ParameterSetName -ne "Existing")
				{
					[System.String]$Body = ConvertTo-Json -InputObject @{"items" = $Items}
					$Splat.Add("Body", $Body)
					$Splat.Add("ContentType", "application/json")

					Write-Verbose -Message "Requesting failover for:`r`n$Body"
				}

				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -WebSession $SessionInfo.Session @Splat
        
				$Temp = ConvertFrom-Json -InputObject $Result.Content

				if ($Result.StatusCode -eq 202)
				{
					Write-Verbose -Message "Failover successfully started."

					if ($PassThru)
					{
						Write-Output -InputObject ([PSCustomObject]$Temp)
					}
				}
				else
				{
					Write-Warning -Message "There was an issue starting the failover: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Invoke-CEMachineTest {
	<#
		.SYNOPSIS
			Launches a new test for the specified instances.

		.DESCRIPTION
			This cmdlet invokes a new test run of the specified instances.

		.PARAMETER Ids
			The ids of the instances to perform a new test for.

		.PARAMETER PointInTime
			An array of hashtables specifying the machine Id and Point In Time Id to test. For example, 

			-PointInTime @(@{"machineId" = "guid"; "pointInTimeId" = "guid" }, @{"machineId" = "guid2"})

			In this case, the first machine uses the specified pointInTimeId, while the second machine uses the latest pointInTime since that property was omitted.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Invoke-CEMachineTest -Ids @("781ca752-d88f-4408-a37d-90e247f3d569", "681cae52-f88f-4290-a37d-8ae276f3d6da")

			This runs a new test for 2 instances.

		.INPUTS
			System.Guid[]

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject	
	
			This is a JSON representation of the output:
			{
			  "status": "PENDING",
			  "type": "TEST",
			  "id": "string",
			  "log": [
				{
				  "message": "string",
				  "logDateTime": "2017-09-10T14:19:39Z"
				}
			  ]
			}

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH", DefaultParameterSetName = "Latest")]
	[OutputType([PSCustomObject])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "Latest")]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid[]]$Ids = @(),

		[Parameter(Mandatory = $true, ParameterSetName = "PointInTime")]
		[ValidateNotNull()]
		[System.Collections.Hashtable[]]$PointInTime = @(),

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/performTest"

			$Items = @()

			switch ($PSCmdlet.ParameterSetName)
			{
				"Latest" {

					foreach ($Item in $Ids)
					{
						$Items += @{"machineId" = $Item}
					}

					break
				}
				"PointInTime" {

					foreach ($Item in $PointInTime)
					{
						[System.Collections.Hashtable]$Machine = @{}

						if ($Item.ContainsKey("machineId"))
						{
							 $Machine.Add("machineId", $Item["machineId"])

							if ($Item.ContainsKey("pointInTimeId"))
							{
								$Machine.Add("pointInTimeId", $Item["pointInTimeId"])
							}

							$Items += $Machine
						}
						else
						{
							throw "The PointInTime array contained an item without a machineId property, this is required for each object."
						}
					}

					break
				}
				default {
					throw "Encountered an unknown parameter set $($PSCmdlet.ParameterSetName)."
					break
				}
			}

			$ConfirmMessage = @"
This test will launch a new instance for each of the launchable Source instances that you have selected.

In addition, the Source instance will be marked as "tested" on this date.

Note:
Any previously launched versions of these instances (including any associated cloud resources that were created by CloudEndure) will be deleted.
"@
			$WhatIfDescription = "Ran test for $($Ids.Length) instance$(if ($Ids.Length -gt 1) { "s" })."
			$ConfirmCaption = "Test $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			[System.String]$Body = ConvertTo-Json -InputObject @{"items" = $Items}

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Requesting tests for:`r`n$Body"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $SessionInfo.Session

				# 202 = Accepted
				if ($Result.StatusCode -eq 202)
				{
					Write-Verbose -Message "Test successfully initiated."
					
					if ($PassThru)
					{
						Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
					}
				}
				else
				{
					Write-Warning -Message "There was an issue launching the test: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Invoke-CEMachineCutover {
	<#
		.SYNOPSIS
			Launches a cutover for the specified instances.

		.DESCRIPTION
			This cmdlet invokes a cutover of the specified instances.

		.PARAMETER Ids
			The ids of the instances to perform a cutover for.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Invoke-CEMachineCutover -Ids @("781ca752-d88f-4408-a37d-90e247f3d569", "681cae52-f88f-4290-a37d-8ae276f3d6da")

			This runs a cutover for 2 instances.

		.INPUTS
			System.Guid[]

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject	
	
			This is a JSON representation of the output:
			{
			  "status": "PENDING",
			  "type": "TEST",
			  "id": "string",
			  "log": [
				{
				  "message": "string",
				  "logDateTime": "2017-09-10T14:19:39Z"
				}
			  ]
			}

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject[]])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
	}

	Process {
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/performCutover?useExistingMachines=false"

			$ConfirmMessage = @"
This Cutover will launch a new instance for each of the launchable Source instances that you have selected.

In addition, the Source instance will be marked as "Cutover" on this date.

Note:
Any previously launched versions of these instances (including any associated cloud resources that were created by CloudEndure) will be deleted.
"@
			$WhatIfDescription = "Cutover $($Ids.Length) instance$(if ($Ids.Length -gt 1) { "s" })."
			$ConfirmCaption = "Cutover $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			$Body = @{"items" = @()}

			foreach ($Id in $Ids)
			{
				$Body.items.Add(@{"machineId" = $Id})
			}

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Requesting cutover for:`r`n $(ConvertTo-Json -InputObject $Body)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -Body (ConvertTo-Json -InputObject $Body) -ContentType "application/json" -WebSession $SessionInfo.Session

				# 202 = Accepted
				if ($Result.StatusCode -eq 202)
				{
					Write-Verbose -Message "Cutover successfully initiated."
					
					if ($PassThru)
					{
						Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content))
					}
				}
				else
				{
					Write-Warning -Message "There was an issue launching the cutover: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Get-CEJobs {
    <#
        .SYNOPSIS
           Gets the log information from active CE jobs.

        .DESCRIPTION
            The cmdlet lists all of log information about a currently running CE jobs.

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEJobs

            Gets the log data for active jobs.

        .INPUTS
			None

        .OUTPUTS
			System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

			This is a JSON representation of the returned array:
			[
				{
				  "status": "PENDING",
				  "type": "TEST",
				  "id": "string",
				  "log": [
					{
					  "message": "string",
					  "logDateTime": "2017-09-10T14:19:39Z"
					}
				  ]
				}
			]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Management.Automation.PSCustomObject[]])]
    Param(
		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$Id = [System.Guid]::Empty,

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
    )

    Begin {        
    }

    Process {
        $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/jobs"

			if ($Id -ne [System.Guid]::Empty)
			{
				$Uri += "/$($Id.ToString())"
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Result.StatusCode -eq 200)
			{
				if ($Id -ne [System.Guid]::Empty)
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
				}
				else
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
				}
			}										
			else
			{
				Write-Warning -Message "There was an issue getting the jobs: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Invoke-CEReplicaCleanup {
	<#
		.SYNOPSIS
			Spawns a cleanup job to remove the specified target machines from the cloud.

		.DESCRIPTION
			Spawns a cleanup job to remove the specified target machines from the cloud.

		.PARAMETER Ids
			The list of replica IDs to delete (corresponding to the 'replica' field in the machine object).

		.PARAMETER ProjectId
			The project Id to use to retrieve the details. This defaults to the current project retrieved from the login.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			Returns the job created by the cmdlet.

		.INPUTS
			System.Guid[]

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject

			This is a JSON representation of the returned value:
			{
			  "status": "PENDING",
			  "type": "TEST",
			  "id": "string",
			  "log": [
				{
				  "message": "string",
				  "logDateTime": "2017-09-10T14:19:39Z"
				}
			  ]
			}

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 9/11/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid[]]$Ids = @(),

		[Parameter()]
		[ValidateScript({
			$_ -ne [System.Guid]::Empty
		})]
		[System.Guid]$ProjectId = [System.Guid]::Empty,

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty
	)

	Begin {
	}
	
	Process {
		 $SessionInfo = $null

        if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
			$Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($ProjectId -eq [System.Guid]::Empty)
			{
				$ProjectId = $SessionInfo.ProjectId
			}

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$ProjectId/replicas"

			[System.String]$Body = ConvertTo-Json -InputObject @{"replicaIDs" = $Ids}

			$ConfirmMessage = @"
This cleanup will remove the specified target machines from the cloud.
"@
			$WhatIfDescription = "Cleaned up $($Ids.Length) instance$(if ($Ids.Length -gt 1) { "s" })."
			$ConfirmCaption = "Cleanup $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Delete -Body $Body -ContentType "application/json" -WebSession $SessionInfo.Session
        
				if ($Result.StatusCode -eq 202)
				{
					Write-Verbose -Message "Cleanup successfully started."

					if ($PassThru)
					{
						Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
					}
				}
				else
				{
					Write-Warning -Message "There was an issue launching the cleanup: $($Result.StatusCode) $($Result.StatusDescription) - $($Result.Content)"
				}
			}
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

#endregion

#region Misc

Function Get-CEWindowsInstaller {
	<#
        .SYNOPSIS
			Downloads the CloudEndure windows installer.

        .DESCRIPTION
			The cmdlet downloads the installer to a location you specify.

        .PARAMETER Destination
			The location the installer should be downloaded to. This can be either a folder or a file name, such as

			c:\downloads or c:\downloads\installer.exe. If a filename is not specified, the filename of the file will be used.
            
        .EXAMPLE
            Get-CEWindowsInstaller -Destination c:\

            Downloads the windows installer to the c: drive.

        .INPUTS
            System.String

        .OUTPUTS
           None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Destination
    )

    Begin {        
    }

    Process {

		if (Test-Path -Path $Destination -PathType Container)
		{
			$Destination = Join-Path -Path $Destination -ChildPath "installer_win.exe"
		}
		else {
			# The regex is starts with c: or \ and then one or more \dir pieces and then an extension with .ab with 2 or more characters
			# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx Defines the non-allowed file path characters
			if ($Destination -imatch "^(?:[a-zA-Z]:|\\)(?:\\[^<>:`"\/\\|\?\*]+)+\.[^<>:`"\/\\|\?\*]{2,}$")
			{
				# Then the provided path is a file name, make sure the directory exists
				
				[System.IO.FileInfo]$FileInfo = New-Object -TypeName System.IO.FileInfo($Destination)
				if (-not (Test-Path -Path $FileInfo.Directory.FullName))
				{
					New-Item -Path $FileInfo.Directory.FullName -ItemType Directory
				}
			}
			else
			{
				# Treat the path as a directory, make sure it exists
				if (-not (Test-Path -Path $Destination))
				{
					New-Item -Path $Destination -ItemType Directory
				}

				$Destination = Join-Path -Path $Destination -ChildPath "installer_win.exe"
			}
		}

		# Now we know the folder for the destination exists and the destination path includes a file name
		[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $script:Installer -OutFile $Destination
    }

    End {
    }
}

#endregion