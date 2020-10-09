<#
.SYNOPSIS
Add or remove allowed or denied CyberArk OPM commands to a specific account 
.DESCRIPTION
Script built to demonstrate utilizing CyberArk Application Access Manager Central Credential Provider (CCP),
CyberArk Restful API, and OPM to automate rule additions and removals for account level permissions.
.PARAMETER task
Parameter for switch statement - valid options are "add" or "remove".
Utilize "add" to add an OPM statement to an account for a user.
Utilize "remove" to remove an existing OPM statement from an account.
.PARAMETER username
Parameter defining the user that will be impacted by the change requested
.PARAMETER accountname
Paramter defining the account name which will have permissions added or removed (e.g. root)
.PARAMETER address
Parameter defining the target system addresss (e.g. 192.168.10.10 or somehostname)
.PARAMETER policy
Parameter defining the policy name (e.g. UnixviaSSH)
.PARAMETER command
Command statement for OPM rule (e.g. /(.*)?/(.*)?/bin passwd(\s)?(.*)?)
.PARAMETER type
Parameter that defines the rule statement, valid options are "Allow" or "Deny".
Utilize "Allow" to whitelist a specific command.
Utilize "Deny" to blacklist a specific command.
.EXAMPLE
OPMAutomation.ps1 -task add -username Paul -accoutname Root -address 192.168.10.10 -policy UnixviaSSH -command "(.*)?/(.*)?/bin passwd(\s)?(.*)?" -type Allow 
Above example would provide the User Paul with the ability to run the "passwd" command on host 192.168.10.10 as the root account.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$task,
    [Parameter(Mandatory=$true)]
    [string]$username,
    [Parameter(Mandatory=$true)]
    [string]$accountname,
    [Parameter(Mandatory=$true)]
    [string]$address,
    [Parameter(Mandatory=$true)]
    [string]$policy,
    [Parameter(Mandatory=$true)]
    [string]$command,
    [Parameter(Mandatory=$true)]
    [string]$type
    )

# Add command - Utilizes all parameters
Function Add-Command {
    write-host "`n$(Get-Date) | INFO | Generating authorization token vault username"
    Try {
        New-PASSession -Credential $Credential -BaseURI https://components.cyberarkdemo.com -type ldap -ErrorAction Stop
        Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | New PAS Session Established"
    } Catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
    }
    write-host "`n$(Get-Date) | INFO | Adding Permissions to Account $accountname for User $username"
    Try {
        Add-PASAccountACL -AccountPolicyID $policy -AccountAddress $address -AccountUserName $accountname -Command $command -CommandGroup $false -PermissionType $type -UserName $username
        Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $accountname account Updated - OPM Permissions Added"
    } Catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
    }
}

# Remove command - searches based on user and command
Function Remove-Command {
    write-host "`n$(Get-Date) | INFO | Generating authorization token vault username"
    Try {
        New-PASSession -Credential $Credential -BaseURI https://components.cyberarkdemo.com -type ldap -ErrorAction Stop
        Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | New PAS Session Established"
    } Catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
    }
    write-host "`n$(Get-Date) | INFO | Removing Permissions to Account $accountname for User $username"
    Try {
        Get-PASAccount -keywords $accountname | Get-PASAccountACL | Where-Object {$_.Command -eq "$command" -and $_.PermissionType -eq "$type" -and $_.UserName -eq "$username"} | Remove-PASAccountACL       
        Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $accountname account Updated - OPM Permissions Removed"
    } Catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
    }
}

# Retrieve's Credential for REST API interaction
function Get-AIMPassword ([string]$PVWA_URL, [string]$AppID, [string]$Safe, [string]$ObjectName) {
    Write-host "`n$(Get-Date) | INFO | Retrieving credential for REST API use via CCP"
    $fetchAIMPassword = "${PVWA_URL}/AIMWebService/api/Accounts?AppID=${AppID}&Safe=${Safe}&Folder=Root&Object=${ObjectName}"
    try {
        $response = Invoke-RestMethod -Uri $fetchAIMPassword -Method GET -ContentType "application/json" -ErrorVariable aimResultErr
        Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $($response.UserName) credentials obtained"
        Return $response
    }
    catch {
        Write-Host -ForegroundColor Red "StatusCode: " $_.Exception.Response.StatusCode.value__
        Write-Host -ForegroundColor Red "StatusDescription: " $_.Exception.Response.StatusDescription
        Write-Host -ForegroundColor Red "Response: " $_.Exception.Message
        Return $false
    }
}

# Update the PVWA_URL, AppID, Safe, and ObjectName to match your environment.
Try {
    $response = Get-AIMPassword -PVWA_URL "https://components.cyberarkdemo.com" -AppID "OPM_Control" -Safe "OPMControl" -ObjectName "opmcontrol"
    Write-host "`n$(Get-Date) | INFO | Generating secured credentials for API use"
    $securePassword = ConvertTo-SecureString -String $response.content -AsPlainText -Force -ErrorAction Stop 
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $response.UserName, $SecurePassword -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | CyberArk management API credentials created"
} Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
}

# Perform task based on user input
Switch ($task)
{
    "add" {Add-Command}
    "remove" {Remove-Command}
    }
