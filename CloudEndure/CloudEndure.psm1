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
	"AWS" = "4c7b3582-9e73-4866-858a-8e1ac6e818b3"
}

[System.Collections.Hashtable]$script:Sessions = @{}

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

		[Parameter()]
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

		if ((Get-Member -InputObject $Json -Name $ProfileName -MemberType Properties) -ne $null) {
			Write-Warning -Message "The profile $ProfileName is being overwritten with new data."
			$Json.$ProfileName =  $Profile
		}
		else {
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
		[ValidateSet("v12")]
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
		if ($PSCmdlet.ParameterSetName -eq "Profile")
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

Function Get-CEMachine {
     <#
        .SYNOPSIS
           Gets a list of CE machines in an account or a specific CE machine.

        .DESCRIPTION
            The cmdlet lists all of the CE machines in the account if no Id is provided. If an Id is provided, then that specific machine is fetched.

		.PARAMETER Id
			The Id of the instance to get. If this is not specified, all instances are returned.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEMachine

            Lists all of the CE machines in the account.

		.EXAMPLE
			Get-CEMachine -Id 9f620e77-3f2e-4df3-bc37-ec4ee736d92f

			Gets details for the machine specified.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
    #>
    [CmdletBinding()]
	[OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

        [Parameter(ValueFromPipeline = $true)]
        [System.Guid]$Id = [System.Guid]::Empty
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/machines"

			if ($Id -ne [System.Guid]::Empty) {
				$Uri += "/$($Id.ToString())"
			}
			else {
				$Uri += "?all=true"
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			$Temp = ConvertFrom-Json -InputObject $Result.Content

			if ($Id -eq [System.Guid]::Empty) {
				Write-Output -InputObject $Temp.Items
			}
			else {
				Write-Output -InputObject $Temp
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

		.PARAMETER Ids
			The Ids of the instances to remove from CloudEndure.

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
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
	[OutputType()]
    Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[Switch]$Force
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/machines"

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
        
				if ($Result.StatusCode -eq 204 -or $Result.StatusCode -eq 200)
				{
					Write-Verbose -Message "Machine(s) $([System.String]::Join(",", $Ids)) successfully deleted."
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

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEJobs

            Gets the log data for active jobs.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/jobs"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Get-CELicenses {
	<#
        .SYNOPSIS
           Gets the current state of license information.

        .DESCRIPTION
            The cmdlet lists the license information about the specified account.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CELicenses

            Retrieves the licenses in the account using the default session context.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/licenses"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}

Function Get-CECloudConfiguration {
	<#
        .SYNOPSIS
           Gets basic information about the destination cloud environment.

        .DESCRIPTION
            The cmdlet retrieves information about the destination cloud.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CECloudConfiguration

            Retrieves the cloud configuration of the current account.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$($SessionInfo.CloudCredentials)"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
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

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEReplicationConfiguration

            Retrieves the replication configuration of the current account.

        .INPUTS
            None or System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
		[Parameter(ValueFromPipeline = $true)]
		[System.Guid]$Id = [System.Guid]::Empty,

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
			# This REST API doesn't support supplying the Id as part of the URL
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/replicationConfigurations"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($Id -ne [System.Guid]::Empty)
			{
				Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content).Items | Where-Object {$_.Id -ieq $Id.ToString() } | Select-Object -First 1)
			}
			else
			{
				Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
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

		.PARAMETER Id
			The replication configuration id.

		.PARAMETER ProxyUrl
			The url of the source proxy to use for outbound connectivity. Specify a URL and port like https://myproxy.contoso.com:8443. Leave blank to not use a proxy.

		.PARAMETER SubnetId
			Specify the subnet Id that the replication servers will be launched in.

		.PARAMETER UsePrivateIp
			Set this parameter to true to use a VPN, DirectConnect, ExpressRoute, or GCP Carrier Interconnect/Direct Peering.

		.PARAMETER VolumeEncryptionKey
			Specify the KMS key to use to encrypt the EBS volumes being written to by the replication instances.

		.PARAMETER ReplicationTags
			Specify the tags that will be applied to CE replication resources.

		.PARAMETER Config
			You can provide a replication config with these properties:

			{
				"proxyUrl": "", 
				"replicationTags": [
					{"key": "keyName", "value": "keyValue"}
				], 
				"replicatorSecurityGroupIDs": [
					"sg-b4c724c4"
				], 
				"subnetId": "subnet-421d476c", 
				"usePrivateIp": false, 
				"volumeEncryptionKey": ""
			}

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			Specify to return the updated config to the pipeline.

		.EXAMPLE
			Set-CEReplicationConfiguration -Id 8cdf36d4-6668-44a9-9cfe-16cb93538a79 -SubnetId "subnet-421d476c"

			Updates the existing replication configuration to specify that replication servers should be deployed in subnet-421d476c.

		.INPUTS
            None

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/22/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Guid]$Id,

		[Parameter(ParameterSetName = "Config", Mandatory = $true)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Config = @{},

        [Parameter(ParameterSetName = "IndividualAWS")]
        [ValidateNotNull()]
        [System.String]$ProxyUrl,

        [Parameter(ParameterSetName = "IndividualAWS")]
        [System.Boolean]$UsePrivateIp,

		[Parameter(ParameterSetName = "IndividualAWS")]
		[System.Collections.Hashtable]$ReplicationTags,

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

			[System.Collections.Hashtable]$CECloud = Get-CETargetCloud -Session $DynSession | ConvertTo-Hashtable

			# Create the dictionary 
			$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		
			if ($Id -ne $null -and $Id -ne [System.Guid]::Empty) 
			{
				switch ($CECloud.Cloud)
				{
					"AWS" {
						$SubnetMapping = @{}
						$VpcMapping = @{}
			
						$CECloud.Subnets | ForEach-Object {
							if ($_.Name -ne "Default") {
								$SubnetMapping.Add($_.Name, $_.SubnetId)
								$VpcMapping.Add($_.SubnetId, $_.NetworkId)
							}
						}

						$private:NetworkId = ""

						if ($CECloud.Subnets.Length -gt 0) 
						{
							#region SubnetIDs

							New-DynamicParameter -Name "SubnetId" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet ($CECloud.Subnets | Select-Object -ExpandProperty Name) -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

							#endregion
						}

						if ($CECloud.VolumeEncryptionKeys.Length -gt 0)
						{
							#region KMS

							[System.Collections.ArrayList]$KMSSet = @()
							$KMSSet += $CECloud.VolumeEncryptionKeys | Where-Object {$_.KeyId -ne $null } | Select-Object -ExpandProperty KeyId
							$KMSSet += "Default"
							$KMSSet += [System.String]::Empty

							New-DynamicParameter -Name "VolumeEncryptionKey" -Type ([System.String[]]) -ParameterSets @("IndividualAWS") -ValidateSet $KMSSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

							#endregion
						}

						$Type = Import-UnboundParameterCode -PassThru
						# The subnet Id here is the verbose version of the subnet selected by the user
						[System.String]$Subnet = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "SubnetId", -1))
			
						# Select either the provided subnet or the existing one to see if we need to process
						# the security groups
						[System.String]$SubnetId = [System.String]::Empty

						if (-not [System.String]::IsNullOrEmpty($Subnet))
						{
							if ($SubnetMapping.ContainsKey($Subnet))
							{
								$SubnetId = $SubnetMapping.$Subnet
							}
						}
						else
						{
							[System.Collections.Hashtable]$ExistingConfig = Get-CEReplicationConfiguration -Id $Id | ConvertTo-Hashtable

							if (-not [System.String]::IsNullOrEmpty($ExistingConfig.SubnetId))
							{
								$SubnetId = $ExistingConfig.SubnetId
							}
						}

						# If the selected subnet was "Default", then it won't be in the mapping, and then we won't populate
						# security groups since the only option is create new

						if (-not [System.String]::IsNullOrEmpty($SubnetId))
						{
							# Set the network Id based on the selected subnet so we can get the right security groups as options
							$private:NetworkId = $VpcMapping[$SubnetId]

							#region SecurityGroups
							[System.Collections.ArrayList]$SGSet = @($CECloud.SecurityGroups | Where-Object {$_.NetworkId -eq $private:NetworkId} | Select-Object -ExpandProperty SecurityGroupId)
							$SGSet += [System.String]::Empty

							New-DynamicParameter -Name "ReplicatorSecurityGroupIDs" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

							#endregion
						}

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
			[System.Collections.Hashtable]$ExistingConfig = Get-CEReplicationConfiguration -Id $Id | ConvertTo-Hashtable

			# If a config hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Config")
			{
				# Convert the parameters specified into a hashtable

                $Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator())
                {
                    $Params.Add($Item.Key, ($Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key))
                }
                
                $Config = @{}

                $RuntimeParameterDictionary.GetEnumerator() | ForEach-Object {
                     [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 
                     if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                     {
                        $ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
                        $Params.Add($Param.Name, $ParameterSets)
                     }
                }

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName))
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

								$Config.Add($Item.Key, $Tags)
							}
							elseif ($Item.Key -ieq "SubnetId") {
								$Config.Add($Item.Key, $SubnetMapping[$PSBoundParameters[$Item.Key]])
							}
							else {
								$Config.Add($Item.Key, $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			# Merge the original and new blueprint
			[System.Collections.Hashtable]$NewConfig = Merge-HashTables -Source $ExistingConfig -Update $Config

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/replicationConfigurations/$($Id.ToString())"

			$ConfirmMessage = "Are you sure you want to update the replication configuration?"

			$WhatIfDescription = "Updated configuration to $(ConvertTo-Json -InputObject $NewConfig)"
			$ConfirmCaption = "Update Replication Configuration"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Sending updated config $(ConvertTo-Json -InputObject $NewConfig)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -Body (ConvertTo-Json -InputObject $NewConfig) -ContentType "application/json" -WebSession $SessionInfo.Session
	
				if ($PassThru) 
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
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

Function New-CEReplicationConfiguration {
	<#
		.SYNOPSIS
			Creates a new CE replication configuration.

		.DESCRIPTION
			This cmdlet is used to create a new CE replication configuration for a specific CE account.

		.PARAMETER ProxyUrl
			The url of the source proxy to use for outbound connectivity. Specify a URL and port like https://myproxy.contoso.com:8443. Leave blank to not use a proxy.

		.PARAMETER SubnetId
			Specify the subnet Id that the replication servers will be launched in.

		.PARAMETER UsePrivateIp
			Set this parameter to true to use a VPN, DirectConnect, ExpressRoute, or GCP Carrier Interconnect/Direct Peering.

		.PARAMETER VolumeEncryptionKey
			Specify the KMS key to use to encrypt the EBS volumes being written to by the replication instances.

		.PARAMETER ReplicationTags
			Specify the tags that will be applied to CE replication resources.

		.PARAMETER Config
			You can provide a replication config with these properties:

			{
				"proxyUrl": "", 
				"replicationTags": [
					{"key": "keyName", "value": "keyValue"}
				], 
				"region" : "114b110d-00ad-48d4-a930-90cb3f8cde2e",
				"replicatorSecurityGroupIDs": [
					"sg-b4c724c4"
				], 
				"subnetId": "subnet-421d476c", 
				"usePrivateIp": false, 
				"volumeEncryptionKey": ""
			}

            You cannot specify an updated Source as part of the config file, you must specify that separately.

		.PARAMETER Source
			The source identifier for replication. 

		.PARAMETER Destination
			The destination indentifier for replication.			

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			Specify to return the updated config to the pipeline.

		.EXAMPLE
			New-CEReplicationConfiguration -SubnetId "subnet-421d476c" -Target "us-east-1" -Source "Generic"

			Creates a new CE replication configuration to specify that replication will be sent to AWS US-East-1, replication servers should be deployed in subnet-421d476c, and the source is a generic location.

		.INPUTS
            None

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/22/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
    Param(
		[Parameter(ParameterSetName = "Config", Mandatory = $true)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Config = @{},

        [Parameter(ParameterSetName = "IndividualAWS")]
        [ValidateNotNull()]
        [System.String]$ProxyUrl,

        [Parameter(ParameterSetName = "IndividualAWS")]
        [System.Boolean]$UsePrivateIp = $false,

        [Parameter(ParameterSetName = "IndividualAWS")]
        [System.String]$VolumeEncryptionKey,

		[Parameter(ParameterSetName = "IndividualAWS")]
		[System.Collections.Hashtable]$ReplicationTags,

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

		[System.Collections.Hashtable]$RegionMapping = @{"Generic" = "f54420d5-3de4-40bb-b35b-33d32ad8c8ef"}

		[PSCustomObject[]]$CERegions = Get-CECloudRegions -Session $DynSession 

		$CERegions | ForEach-Object {
			$RegionMapping.Add($_.Name, $_.Id)
		}

        # Create the dictionary 
		$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		#region Source - The source isn't defined as part of the replication config

		New-DynamicParameter -Name "Source" -Type ([System.String]) -ValidateSet @($RegionMapping.GetEnumerator() | Select-Object -ExpandProperty Key) -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

		#endregion
		
		if ($Config -eq $null -or $Config -eq @{})
		{
			$SubnetMapping = @{}
			$VpcMapping = @{}

			#region Target

			[System.Collections.ArrayList]$TargetSet = $RegionMapping.GetEnumerator() | Select-Object -ExpandProperty Key
			$TargetSet.Remove("Generic")

			New-DynamicParameter -Name "Target" -Type ([System.String]) -ValidateSet $TargetSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

			#endregion

			# Import the unbound parameter checking code from HostUtilities
			$Type = Import-UnboundParameterCode -PassThru
			[System.String]$TargetRegionName = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "Target", -1))

			if (-not [System.String]::IsNullOrEmpty($TargetRegionName))
			{
				if ($RegionMapping.ContainsKey($TargetRegionName))
				{
					$TargetRegionId = $RegionMapping[$TargetRegionName]

					#region SubnetId

					$CERegions | Where-Object {$_.Id -eq $TargetRegionId } | 
						Select-Object -First 1 -ExpandProperty Subnets | 
						# This will filter out the "Default" subnet as it doesn't have an subnetId or networkId property
						Where-Object { -not [System.String]::IsNullOrEmpty($_.Name) -and -not [System.String]::IsNullOrEmpty($_.SubnetId) -and -not [System.String]::IsNullOrEmpty($_.NetworkId) } | 
						ForEach-Object {
							$SubnetMapping.Add($_.Name, $_.SubnetId)
							$VpcMapping.Add($_.SubnetId, $_.NetworkId)
						}

					New-DynamicParameter -Name "SubnetId" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet ($CERegions | Where-Object {$_.Id -eq $TargetRegionId } | Select-Object -First 1 -ExpandProperty Subnets | Select-Object -ExpandProperty Name) -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

					#endregion

					[System.String]$SubnetId = $Type.GetMethod("GetUnboundParameterValue").MakeGenericMethod([System.String]).Invoke($Type, @($PSCmdlet, "SubnetId", -1))

					if (-not [System.String]::IsNullOrEmpty($SubnetId))
					{
                        $Subnet = $SubnetMapping[$SubnetId]

						if (-not [System.String]::IsNullOrEmpty($Subnet) -and $VpcMapping.ContainsKey($Subnet))
						{
							# $VpcId = $CERegions | Where-Object {$_.Id -eq $TargetRegionId} | Select-Object -First 1 | Select-Object -ExpandProperty SecurityGroups | Where-Object {$_.Name -eq $PSBoundParameters["SubnetId"]} | Select-Object -First 1 -ExpandProperty NetworkId
							$VpcId = $VpcMapping[$Subnet]

							#region SecurityGroups

							$SGSet = $CERegions | Where-Object {$_.Id -eq $TargetRegionId} | Select-Object -First 1 | Select-Object -ExpandProperty SecurityGroups | Where-Object {$_.NetworkId -eq $VpcId} | Select-Object -ExpandProperty SecurityGroupId
							$SGSet += [System.String]::Empty

							New-DynamicParameter -Name "ReplicatorSecurityGroupIDs" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

							#endregion
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
		[System.String]$SubnetId = $PSBoundParameters["SubnetId"]
		[System.String]$SecurityGroupIds = $PSBoundParameters["ReplicatorSecurityGroupIDs"]

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
			# This is the default set of properties we can specify for a new replication config
			$DefaultConfig = @{
				"cloudCredentials" = "$($SessionInfo.CloudCredentials)";
                "region" = "";
                "subnetId" = "";
                "replicatorSecurityGroupIDs" = @();
                "volumeEncryptionKey" = "";
                "replicationTags" = @();
                "usePrivateIp" = $false;
                "proxyUrl" = ""
            }
                    
			# If a config hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Config")
			{
				# Convert the parameters specified into a hashtable
				$Params = @{}

				foreach ($Item in (Get-Command -Name $PSCmdlet.MyInvocation.InvocationName).Parameters.GetEnumerator())
                {
                    $Params.Add($Item.Key, ($Item.Value.ParameterSets.GetEnumerator() | Select-Object -ExpandProperty Key))
                }

                $Config = @{}

                $RuntimeParameterDictionary.GetEnumerator() | ForEach-Object {
                     [System.Management.Automation.RuntimeDefinedParameter]$Param = $_.Value 

                     if ($Param.IsSet -and -not $Params.ContainsKey($Param.Name))
                     {
                        $ParameterSets = $Param.Attributes | Where-Object {$_ -is [System.Management.Automation.PARAMETERAttribute] } | Select-Object -ExpandProperty ParameterSetName
                        $Params.Add($Param.Name, $ParameterSets)
                     }
                }

				# Get the parameters for the command
				foreach ($Item in $Params.GetEnumerator())
                {
					# If the parameter is part of the Individual parameter set
					if ($Item.Value.Contains($PSCmdlet.ParameterSetName))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the config
							
							if ($Item.Key -eq "ReplicationTags")
							{
								$Tags = @()
								# We need to convert the hashtable to the tag key/value structure
								$PSBoundParameters[$Item.Key].GetEnumerator() | ForEach-Object {
									$Tags += @{"key" = $_.Key; "value" = $_.Value}
								}

								$Config.Add($Item.Key, $Tags)
							}
                            # The friendly name of the subnet was provided at the command line
                            elseif($Item.Key -eq "SubnetId") {
								$Config.Add($Item.Key, $SubnetMapping[$PSBoundParameters[$Item.Key]])
                            }
							else {
								$Config.Add($Item.Key, $PSBoundParameters[$Item.Key])
							}
						}
					}
				}
			}

			# Merge the updated parameters specified with the default settings
			# This ensures our request has all required properties, even if some are blank
            $Config = Merge-Hashtables -Source $DefaultConfig -Update $Config

			# We need the project to see the original source
            [System.Collections.Hashtable]$CurrentProject = Get-CEProject -Session $Session | ConvertTo-Hashtable

			# We need the current replication config to see the original target
            [System.collections.Hashtable]$CurrentConfig = Get-CEReplicationConfiguration -Id $CurrentProject["replicationConfiguration"] -Session $Session | ConvertTo-Hashtable

			# Build the confirmation messages with warnings about updates to source and destination
            $ConfirmMessage = "The action you are about to perform is destructive!"

            if (-not [System.String]::ISNullOrEmpty($Source))
            {        
				$OriginalSrc = $CurrentProject["source"]
                $OriginalSource = $RegionMapping.GetEnumerator() | Where-Object {$_.Value -eq $OriginalSrc } | Select-Object -First 1 -ExpandProperty Key
                    
                # Do this second so we don't overwrite the original source for the confirm message
				# This will set the updated source for the PATCH request
                $CurrentProject["source"] = $RegionMapping[$Source]

                $ConfirmMessage += "`r`n`r`nChanging your Live Migration Source from $OriginalSource to $Source will cause all current instances to be disconnected from CloudEndure: you will need to reinstall the CloudEndure Agent on all the instances and data replication will restart from zero."
            }

            if (-not [System.String]::IsNullOrEmpty($Target) -or -not [System.String]::IsNullOrEmpty($Config["region"]))
            {
				# If a config with a region wasn't specified, get it from the Target specified
				# The RegionMapping table was built during the dynamic params evaluation
				if ([System.String]::IsNullOrEmpty($Config["region"]))
				{
					$Config["region"] = $RegionMapping[$Target]
				}
                $OriginalTarget = $RegionMapping.GetEnumerator() | Where-Object {$_.Value -eq $CurrentConfig["region"] } | Select-Object -First 1 -ExpandProperty Key

                $ConfirmMessage += "`r`n`r`nChanging your Live Migration Target from $OriginalTarget to $Target will cause all current instances to be disconnected from CloudEndure: you will need to reinstall the CloudEndure Agent on all the instances and data replication will restart from zero."
            }

            $ConfirmMessage += "`r`n`r`nAre you sure you want to continue?"
			$WhatIfDescription = "New replication configuration created: $(ConvertTo-Json -InputObject $Config)"
			$ConfirmCaption = "Create New Replication Configuration"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
                # Send the post request to create a new replication configuration if a new target region was specified
                if (-not [System.String]::IsNullOrEmpty($Config["region"]))
                {
					if ($Config["region"] -ne $Currentconfig["region"] )
					{
						Write-Verbose -Message "Sending config $(ConvertTo-Json $Config)"
						[System.String]$PostUri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/replicationConfigurations"
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

				# Make sure a new source that was different than the old one was specified or that the target region is new
				if ((-not [System.String]::IsNullOrEmpty($Source) -and $CurrentProject["source"] -ne $OriginalSrc) -or $Config["region"] -ne $Currentconfig["region"])
				{
					# Send the patch request to update the project data with the new source, if provided, or the new replication configuration
					# At least 1 of them changed, so we'll always need to send this patch request
					[System.String]$PatchUri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)"

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

Function Remove-CEReplicationConfiguration {
	<#
		.SYNOPSIS
			Removes a replication configuration. NOT YET SUPPORTED!

		.DESCRIPTION
			This cmdlet removes a specified replication configuration. NOT YET SUPPORTED!

		.PARAMETER Id
			The id of the replication configuration to remove.

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
        [System.Guid]$Id,

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
            [System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/replicationConfigurations"
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

Function Get-CEProject {
	<#
        .SYNOPSIS
			Gets basic information about the CE project.

        .DESCRIPTION
			The cmdlet retrieves basic information about the CE project in the CE account.

		.PARAMETER All
			This specifies to retrieve all current projects, instead of the one identified during logon.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEProject -All

            Retrieves all projects.

		.EXAMPLE
			Get-CEProject
			
			Retrieves data about the current project.

        .INPUTS
            None

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
		[Parameter()]
		[Switch]$All,

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
			
			if (-not $All)
			{
				$Uri += "/$($SessionInfo.ProjectId)"
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
			if ($All)
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
            
        .EXAMPLE
            Get-CEBlueprint

            Retrieves the blueprints of the current account.

		.EXAMPLE 
			Get-CEBlueprint -Id 184142f8-a581-4c86-9285-e24382d60d55

			Gets the blueprint matching the provided Id.

        .INPUTS
            None or System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject[] or System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    Param(
		[Parameter(ValueFromPipeline = $true)]
		[System.Guid]$Id = [System.Guid]::Empty,

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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/blueprints"

			if ($Id -ne [System.Guid]::Empty)
			{
				$Uri += "/$($Id.ToString())"
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session
        
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
				"disks":[
					{"name":"c:0","type":"SSD","iops":1000}
				],
				"iamRole":"",
				"instanceType":"c4.large",
				"placementGroup":"",
				"privateIPAction":"COPY_ORIGIN",		# CREATE_NEW or CUSTOM_IP
				"privateIPs":[],
				"publicIPAction":"ALLOCATE",			# DONT_ALLOCATE or AS_SUBNET
				"runAfterLaunch":true,
				"securityGroupIDs":[
					"sg-027c637e"
				],
				"staticIp":"",							# Only set if staticIpAction is EXISTING
				"staticIpAction":"DONT_CREATE",			# CREATE_NEW or EXISTING
				"subnetIDs":[
						"subnet-843598b8"
				],
				"tags":[
					{	
						"key":"test",
						"value":"testing"
					}
				]
			}

		.PARAMETER IAMRole
			The AWS IAM Role to associate with this blueprint.

		.PARAMETER InstanceType
			The instance type to launch the replica as.

		.PARAMETER PlacementGroup
			The placement group to launch the instance in.

		.PARAMETER PrivateIPAction
			The action for the instance's private IP address.

		.PARAMETER PrivateIPs
			If you select CUSTOM for PrivateIPAction, specify the private IPs you want associated with the instance.

		.PARAMETER PublicIPAction
			The action for the instance's ephemeral public IP address.

		.PARAMETER RunAfterLaunch
			Specify true to have the instance started after it is launched or false to leave it in a stopped state.

		.PARAMETER SecurityGroupIds
			The security groups that will be associated with the instance.

		.PARAMETER StaticIP
			If you select ALLOCATE for StaticIPAction, then specify Elatic IP address to associate with the instance.

		.PARAMETER SubnetIDs
			Specify the subnet Id(s) the instance will be associated with.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
		.PARAMETER Tags
			The tags that will be associated with the instance.

		.PARAMETER InstanceId
			The id of the CE instance whose blueprint you want to update.

		.PARAMETER PassThru
			The updated blueprint will be returned to the pipeline.

        .EXAMPLE
            Set-CEBlueprint -InstanceId 47d842b8-ebfa-4695-90f8-fb9ab686c708 -Blueprint @{"IAMRole" = "EC2-InstanceProfile-Public"}

			This adds or updates the IAMRole property for the blueprint to "EC2-InstanceProfile-Public" for the CE instance identified by 47d842b8-ebfa-4695-90f8-fb9ab686c708.

		.EXAMPLE
			Set-CEBlueprint -InstanceId 47d842b8-ebfa-4695-90f8-fb9ab686c708 -IAMRole "EC2-InstanceProfile-Public"

			This adds or updates the IAMRole property for the blueprint to "EC2-InstanceProfile-Public" for the CE instance identified by 47d842b8-ebfa-4695-90f8-fb9ab686c708.

        .INPUTS
            None

        .OUTPUTS
           None or System.Management.Automation.PSCustomObject

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
    [OutputType([PSCustomObject])]
    Param(
		[Parameter(Mandatory = $true)]
        [System.Guid]$InstanceId = [System.Guid]::Empty,

		[Parameter(Mandatory = $true, ParameterSetName = "Blueprint")]
		[System.Collections.Hashtable]$Blueprint = @{},

		[Parameter(ParameterSetName = "IndividualAWS")]
		[ValidateSet("COPY_ORIGIN", "CREATE_NEW", "CUSTOM_IP")]
		[System.String]$PrivateIPAction,

		[Parameter(ParameterSetName = "IndividualAWS")]
		[ValidateSet("ALLOCATE", "DONT_ALLOCATE", "AS_SUBNET")]
		[System.String]$PublicIPAction,

		[Parameter(ParameterSetName = "IndividualAWS")]
		[System.Boolean]$RunAfterLaunch,

		[Parameter(ParameterSetName = "IndividualAWS")]
		[ValidateSet("DONT_CREATE", "CREATE_NEW", "EXISTING")]
		[System.String]$StaticIPAction,

		[Parameter(ParameterSetName = "IndividualAWS")]
		[System.Collections.Hashtable]$Tags,

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

		[System.Collections.Hashtable]$CECloud = Get-CETargetCloud -Session $DynSession | ConvertTo-Hashtable

		# Create the dictionary 
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
		
		if ($InstanceId -ne $null -and $InstanceId -ne [System.Guid]::Empty) 
		{
			[System.Collections.Hashtable]$ExistingBlueprint = Get-CEBlueprint -Session $DynSession -Id $InstanceId | ConvertTo-Hashtable

			switch ($CECloud.Cloud)
			{
				"AWS" {
					$SubnetMapping = @{}
			
					$CECloud.Subnets | ForEach-Object {
						if ($_.Name -ne "Default") {
							$SubnetMapping.Add($_.SubnetId, $_.NetworkId)
						}
					}

					$private:NetworkId = ""

					#region IAMRole

					$IAMSet = $CECloud.IAMRoles
					$IAMSet += [System.String]::Empty

					New-DynamicParameter -Name "IAMRole" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $IAMSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
        
					#endregion

					#region InstanceType

					New-DynamicParameter -Name "InstanceType" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $CECloud.InstanceTypes -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

					#endregion

					if ($CECloud.PlacementGroups.Length -gt 0)
					{
						#region PlacementGroup

						$PlacementSet = $CECloud.PlacementGroups
						$PlacementSet += [System.String]::Empty

						New-DynamicParameter -Name "PlacementGroup" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $PlacementSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
        
						#endregion
					}
		
					if ($CECloud.Subnets.Length -gt 0) 
					{
						#region SubnetIDs

						$SubnetSet = $CECloud.Subnets | Where-Object {$_.SubnetId -ne $null } | Select-Object -ExpandProperty SubnetId
						$SubnetSet += "Default"

						New-DynamicParameter -Name "SubnetIDs" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $SubnetSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion
					}

					if ($CECloud.VolumeEncryptionKeys.Length -gt 0)
					{
						#region KMS

						$KMSSet = $CECloud.VolumeEncryptionKeys | Where-Object {$_.KeyId -ne $null } | Select-Object -ExpandProperty KeyId
						$KMSSet += "Default"
						$KMSSet += [System.String]::Empty

						New-DynamicParameter -Name "VolumeEncryptionKey" -Type ([System.String]) -ParameterSets @("IndividualAWS") -ValidateSet $KMSSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion
					}
			
					if ($PrivateIPAction -eq "CUSTOM_IP" -or $ExistingBlueprint.PrivateIPAction -eq "CUSTOM_IP")
					{
						#region PrivateIPs

						New-DynamicParameter -Name "PrivateIPs" -Type ([System.String[]]) -Mandatory:($PrivateIPAction -eq "CUSTOM_IP") -ParameterSets @("IndividualAWS") -ValidateSet $KMSSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion
					}

					if ($SubnetIDs.Length -gt 0 -or $ExistingBlueprint.SubnetIDs.Length -gt 0)
					{
						# Set the network Id based on the selected subnet so we can get the right security groups as options
						if ($SubnetMapping.ContainsKey($SubnetIDs[0])) {
							$private:NetworkId = $SubnetMapping[$SubnetIDs[0]]
						}
						elseif ($SubnetMapping.ContainsKey($ExistingBlueprint.SubnetIDs[0])) {
							$private:NetworkId = $SubnetMapping[$ExistingBlueprint.SubnetIDs[0]]
						}

						#region SecurityGroups

						$SGSet = $CECloud.SecurityGroups | Where-Object {$_.NetworkId -eq $private:NetworkId}
						$SGSet += [System.String]::Empty

						New-DynamicParameter -Name "SecurityGroupIDs" -Type ([System.String[]]) -ParameterSets @("IndividualAWS") -ValidateSet $SGSet -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null
        
						#endregion
					}

					if ($StaticIPAction -eq "EXISTING" -or $ExistingBlueprint.StaticIPAction -eq "EXISTING")
					{
						#region EIP

						New-DynamicParameter -Name "StaticIP" -Type ([System.String[]]) -Mandatory:($StaticIPAction -eq "EXISTING") -ParameterSets @("IndividualAWS") -ValidateSet $CECloud.StaticIPs -RuntimeParameterDictionary $RuntimeParameterDictionary | Out-Null

						#endregion
					}

					break
				}
				default {
					throw "The cloud environment $($CECloud.Cloud) is not supported by this cmdlet yet."
				}
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
			[System.Collections.Hashtable]$ExistingBlueprint = Get-CEBlueprint -Session $Session -Id $InstanceId | ConvertTo-Hashtable

			# If a blueprint hashtable wasn't provided, build one for the parameter set being used
			if ($PSCmdlet.ParameterSetName -ne "Blueprint")
			{
				# Convert the parameters specified into a hashtable

				$CommandName = $PSCmdlet.MyInvocation.InvocationName

				[System.Collections.Hashtable]$ParamList = (Get-Command -Name  $CommandName).Parameters

				$Blueprint = @{}

				# Get the parameters for the command
				foreach ($Item in $ParamList.GetEnumerator())
				{
					# If the parameter is part of the Individual parameter set
					if ($Item.Value.ParameterSets.ContainsKey($PSCmdlet.ParameterSetName))
					{
						# Check to see if it was supplied by the user
						if ($PSBoundParameters.ContainsKey($Item.Key))
						{
							# If it was, add it to the blueprint object

							if ($Item.Key -eq "Tags")
							{
								$Tags = @()
								# We need to convert the hashtable to the tag key/value structure
								$PSBoundParameters[$Item.Key].GetEnumerator() | ForEach-Object {
									$Tags += @{"key" = $_.Key; "value" = $_.Value}
								}

								$Blueprint.Add($Item.Key, $Tags)
							}
							else {
								$Blueprint.Add($Item.Key, $PSBoundParameters[$Item.Key])
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

			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/blueprints/$($NewBluePrint.Id)"

			$ConfirmMessage = "Are you sure you want to update the blueprint configuration?"

			$WhatIfDescription = "Updated blueprint to $(ConvertTo-Json -InputObject $NewBluePrint)"
			$ConfirmCaption = "Update Blueprint"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Body (ConvertTo-Json -InputObject $NewBluePrint) -ContentType "application/json" -Method Patch -WebSession $SessionInfo.Session
        
				if ($PassThru)
				{
					Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
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

Function New-CEInstallationToken {
	<#
        .SYNOPSIS
			Replaces the current installation token with a new one.

        .DESCRIPTION
			The cmdlet creates a new installation token and invalidates the old one.

		.PARAMETER PassThru
			If specified, the new installation token will be returned to the pipeline.

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
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/replaceAgentInstallationToken"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -WebSession $SessionInfo.Session
        
			if ($PassThru) 
			{
				Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content).AgentInstallationToken
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
			LAST UPDATE: 8/24/2017
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

			Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content).AgentInstallationToken
		}
		else 
		{
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

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CEBlueprints

            Retrieves the blueprints of the current account.

        .INPUTS
            None

        .OUTPUTS
           None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding()]
    [OutputType()]
    Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Enabled")]
		[Switch]$Enabled,

		[Parameter(Mandatory = $true, ParameterSetName = "Disabled")]
		[Switch]$Disabled,

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

			if ($Enabled) {
				$Ids += $SessionInfo.ProjectId
			}

			[System.String]$Body = ConvertTo-Json -InputObject @{"id" = $SessionInfo.User.Id; "settings" = @{"sendNotifications" = @{"projectIds" = $Ids}}} -Depth 3

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session

			if ($Result.StatusCode -eq 200) {
				if ($Enabled) {
					Write-Verbose -Message "Email notifications enabled for $($SessionInfo.User.Username)."
				}
				else {
					Write-Verbose -Message "Email notifications disabled for $($SessionInfo.User.Username)."
				}
			}
			else {
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

Function Stop-CEDataReplication {
	<#
        .SYNOPSIS
           Stops data replication for specified instances.

        .DESCRIPTION
            The cmdlet stops data replication for specified instances. The instances will remain in the console, and replication can be started from zero again.

		.PARAMETER Ids
			The Ids of the instances to stop replication on.

		.PARAMETER PassThru
			If specified, the cmdlet will return updated instance information.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Stop-CEReplication -Ids e0dc06ba-86b5-4c4c-b25b-20a68089c797 -Force

            Stops replication for the specified instance.

        .INPUTS
            System.Guid[]

        .OUTPUTS
           None or PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
	[OutputType([PSCustomObject[]])]
    Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/stopReplication"

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
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session
        
				if ($Result.StatusCode -eq 200)
				{
					Write-Verbose -Message "Replication successfully stopped for machine(s) $([System.String]::Join(",", $Ids))."
				}

				if ($PassThru)
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
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

Function Start-CEDataReplication {
	<#
        .SYNOPSIS
           Starts data replication for specified instances.

        .DESCRIPTION
            The cmdlet starts data replication for specified instances. 

		.PARAMETER Ids
			The Ids of the instances to start replication for.

		.PARAMETER PassThru
			If specified, the cmdlet will return updated instance information.

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Start-CEReplication -Ids e0dc06ba-86b5-4c4c-b25b-20a68089c797 -Force

            Starts replication for the specified instance.

        .INPUTS
            System.Guid[]

        .OUTPUTS
           PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/17/2017
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
	[OutputType([PSCustomObject[]])]
    Param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
			$script:Sessions.ContainsKey($_.ToLower())
		})]
        [System.String]$Session = [System.String]::Empty,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Guid[]]$Ids = @(),

		[Parameter()]
		[Switch]$PassThru,

		[Parameter()]
		[Switch]$Force
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/startReplication"

			[System.String]$Body = ConvertTo-Json -InputObject @{"machineIDs" = $Ids}

			$ConfirmMessage = @"
Are you sure you want to start data replication?

If you continue, you will begin to incur additional costs from Amazon Web Services for data transfer, storage, compute and other resources.

(selected instances for which data replication is already started will not be affected)
"@

			$WhatIfDescription = "Started replication for CE Instances $([System.String]::Join(",", $Ids))"
			$ConfirmCaption = "Start Data Replication for $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -ContentType "application/json" -Body $Body -WebSession $SessionInfo.Session
        
				if ($Result.StatusCode -eq 200)
				{
					Write-Verbose -Message "Replication successfully stopped for machine(s) $([System.String]::Join(",", $Ids))."
				}

				if ($PassThru)
				{
					Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content).Items
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

Function Get-CETargetCloud {
	<#
        .SYNOPSIS
			Gets information about the destination cloud environment.

        .DESCRIPTION
			The cmdlet retrieves information about the target/destination cloud environment.

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
			LAST UPDATE: 8/22/2017
    #>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
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
		if (-not [System.String]::IsNullOrEmpty($Session)) {
            $SessionInfo = $script:Sessions.Get_Item($Session)
        }
        else {
            $SessionInfo = $script:Sessions.GetEnumerator() | Select-Object -First 1 -ExpandProperty Value
            $Session = $SessionInfo.User.Username
        }

		if ($SessionInfo -ne $null) 
		{
			if ($SessionInfo.Regions.Target.Id -ne $SessionInfo.Regions.Generic.Id)
			{
				[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$($SessionInfo.CloudCredentials)/regions/$($SessionInfo.Regions.Target.Id)"

				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

				Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
			}
			else
			{
				Write-Output -InputObject $SessionInfo.Regions.Generic
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
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
			if ($SessionInfo.Regions.Source.Id -ne $SessionInfo.Regions.Generic.Id)
			{
				[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$($SessionInfo.CloudCredentials)/regions/$()"

				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

				Write-Output -InputObject ([PSCustomObject](ConvertFrom-Json -InputObject $Result.Content))
			}
			else
			{
				Write-Output -InputObject $SessionInfo.Regions.Generic
			}
		}
		else {
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

        .PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.
            
        .EXAMPLE
            Get-CECloudRegion

            Retrieves the details of all regions the destination cloud environment.

		.EXAMPLE
			Get-CECloudRegion -Id 47d842b8-ebfa-4695-90f8-fb9ab686c708

			Retrieves details of the region identified with the supplied Guid.

        .INPUTS
            System.Guid

        .OUTPUTS
           System.Management.Automation.PSCustomObject or System.Management.Automation.PSCustomObject[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/28/2017
    #>
	[CmdletBinding()]
	[OutputType([PSCustomObject], [PSCustomObject[]])]
	Param(
		[Parameter(ValueFromPipeline = $true)]
		[System.Guid]$Id = [System.Guid]::Empty,

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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$($SessionInfo.CloudCredentials)/regions"

			if ($Id -ne [System.Guid]::Empty)
			{
				$Uri += "/$($Id.ToString())"
			}

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			if ($Id -eq [System.Guid]::Empty)
			{
				Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content).Items)
			}
			else 
			{
				Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content))
			}
		}
		else {
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
	}

	End {
	}
}

Function Set-CECloudCredential {
	<#
		.SYNOPSIS
			Sets new cloud credentials for CE to use in the target environment.

		.DESCRIPTION
			This cmdlet sets new credentials that CloudEndure will utilize to launch resources in the target environment.

		.PARAMETER PublicKey
			This is the public key of the public/private key pair. For AWS, this is the AWS Access Key Id.

		.PARAMETER PrivateKey
			This is the private key of the public/private key pair. For AWS, this is the AWS Secret Access Key.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.PARAMETER PassThru
			If specified, the updated cloud credential configuration is passed to the pipeline.

		.EXAMPLE 
			Set-CECloudCredential -PublicKey AKIAPUTJUST34HYMMDRE -PrivateKey g3t89hLRcAhhq67KB8LNdx2C+9twO49uvajFF1Wa

			This sets new credentials for the current CE account.

		.EXAMPLE
			$Creds = @{
				"PublicKey" = "AKIAPUTJUST34HYMMDRE";
				"PrivateKey" = "g3t89hLRcAhhq67KB8LNdx2C+9twO49uvajFF1Wa"
			}
	
			$Creds | New-Object PSObject -Property $_ | Set-CECloudCredential

			This example shows how the parameters can be supplied via the pipeline by property name.

		.INPUTS
			None

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject
			
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
		[ValidateLength(20, 20)]
		[System.String]$PublicKey,

		[Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
		[System.String]$PrivateKey,

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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/cloudCredentials/$($SessionInfo.CloudCredentials)"

			$CloudCreds = Get-CECloudConfiguration -Session $Session

			$Body = @{
				"accountIdentifier" = "$($CloudCreds.AccountIdentifier)";
				"publicKey" = $PublicKey;
				"privateKey" = $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PrivateKey)));
				"id" = "$($CloudCreds.Id)";
				"cloudId" = "$($CloudCreds.Cloud)"
			}

			$ConfirmMessage = "Are you sure you want to update the cloud credentials?"
			$WhatIfDescription = "Updated credentials."
			$ConfirmCaption = "Update CE Credentials"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				Write-Verbose -Message "Sending updated config:`r`n $(ConvertTo-Json -InputObject $Body)"
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Patch -Body (ConvertTo-Json -InputObject $Body) -ContentType "application/json" -WebSession $SessionInfo.Session

				if ($PassThru)
				{
					Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content))
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
			LAST UPDATE: 8/24/2017
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

			$Body = @{
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
						Write-Output -InputObject ([PSCustomObject[]](ConvertFrom-Json -InputObject $Result.Content))
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

Function Invoke-CEMachineTest {
	<#
		.SYNOPSIS
			Launches a new test for the specified instances.

		.DESCRIPTION
			This cmdlet invokes a new test run of the specified instances.

		.PARAMETER Ids
			The ids of the instances to perform a new test for.

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Invoke-CEMachineTest -Ids @("781ca752-d88f-4408-a37d-90e247f3d569", "681cae52-f88f-4290-a37d-8ae276f3d6da")

			This runs a new test for 2 instances.

		.INPUTS
			System.Guid[]

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject		

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Guid[]]$Ids = @(),

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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/performTest"

			$ConfirmMessage = @"
This test will launch a new instance for each of the launchable Source instances that you have selected.

In addition, the Source instance will be marked as "tested" on this date.

Note:
Any previously launched versions of these instances (including any associated cloud resources that were created by CloudEndure) will be deleted.
"@
			$WhatIfDescription = "Ran test for $($Ids.Length) instance$(if ($Ids.Length -gt 1) { "s" })."
			$ConfirmCaption = "Test $($Ids.Length) Instance$(if ($Ids.Length -gt 1) { "s" })"

			$Body = @{"items" = @()}

			foreach ($Id in $Ids)
			{
				$Body.items.Add(@{"machineId" = $Id; "pointInTimeId" = ""})
			}

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Post -Body (ConvertTo-Json -InputObject $Body) -ContentType "application/json" -WebSession $SessionInfo.Session

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

		.PARAMETER Session
            The session identifier provided by New-CESession. If this is not specified, the default session information will be used.

		.EXAMPLE
			Invoke-CEMachineCutover -Ids @("781ca752-d88f-4408-a37d-90e247f3d569", "681cae52-f88f-4290-a37d-8ae276f3d6da")

			This runs a cutover for 2 instances.

		.INPUTS
			System.Guid[]

		.OUTPUTS
			None or System.Management.Automation.PSCustomObject		

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([PSCustomObject[]])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Guid[]]$Ids = @(),

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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/projects/$($SessionInfo.ProjectId)/performCutover?useExistingMachines=false"

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

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2017
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

			Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
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

			This was the data originally returned by the celogin API call.

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
			LAST UPDATE: 8/24/2017

	#>
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
			[System.String]$Uri = "$script:Url/$($SessionInfo.Version)/ceme"

			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Result = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $SessionInfo.Session

			Write-Output -InputObject (ConvertFrom-Json -InputObject $Result.Content)
		}
		else 
		{
			throw "A valid Session could not be found with the information provided. Check your active sessions with Get-CESession or create a new session with New-CESession."
		}
    }

    End {
    }
}