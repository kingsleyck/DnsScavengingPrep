#Requires -Version 3
#Requires -Module ActiveDirectory, DnsServer

function Get-DnsZonesForAclCheck
{
    <# 
    .SYNOPSIS 
        Retrieve the subset of DNS zones where scavenging could be enabled. 
    .EXAMPLE 
        Get-DnsZonesForAclCheck
    #> 
    [CmdletBinding()]

    # setup variables
    $DnsServer = (Get-ADDomainController).Name

    # filter the list of DNS zones down to those where scavenging could be enabled
    Get-DnsServerZone -ComputerName $DnsServer | Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -ne "TrustAnchors" -and $_.ReplicationScope -ne "None" }
}

function Get-BrokenDnsAcls
{
    <# 
    .SYNOPSIS 
        Retrieves DNS records whose ownership and/or ACE no longer allow dynamic updates. Assumes a DnsUpdateProxy account is in use. 
    .EXAMPLE 
        Get-BrokenDnsAcl -ZoneName domain.local -ReplicationScope Domain -DnsUpdateProxy DnsUpdateProxyUser -DhcpServers dhcp1,dhcp2 
     
        Gets A records in domain.local which can't be updated by dynamic DNS registration.
    .EXAMPLE
        Get-DnsZonesForAclCheck | Get-BrokenDnsAcls -DnsUpdateProxy DnsUpdateProxyUser -DhcpServers server
    .PARAMETER DhcpServers
        A list of DHCP servers that may have ownership of records.
    .PARAMETER DnsUpdateProxy
        The name of the DnsUpdateProxy user. This is required and is best practice for secure dynamic updates.
    .PARAMETER ReplicationScope
        The partition in which ZoneName is stored, e.g. Domain, Forest or Legacy.
    .PARAMETER ZoneName
        A primary Active Directory integrated DNS zone.
    #> 

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
	[string]$DnsUpdateProxy,

	[Parameter(Mandatory)]
	[string[]]$DhcpServers,

	[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateSet('Domain','Forest','Legacy')]
        [string]$ReplicationScope,

        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
	[string]$ZoneName
    )

    begin
    {
        # setup vars
        $Domain = Get-ADDomain
        $DomainDN = $Domain.DistinguishedName
        $DomainNB = $Domain.NetBIOSName
        $DomainDnsUpdateProxy = "$DomainNB\$DnsUpdateProxy"

        # validate params here for pipeline optimization
        if (-not (Get-AdUser -Filter { Name -eq $DnsUpdateProxy })){Throw "$DnsUpdateProxy is not a valid AD user object."}
        $DhcpServers | ForEach-Object { if (-not ( Get-ADComputer -Filter { Name -eq $_ } )){Throw "$_ is not a valid AD computer object."}}

        # List of computers, expect secure dynamic updates from Windows only
        $Computers = (Get-AdComputer -Filter * -Properties OperatingSystem | Where-Object { $_.OperatingSystem -like "Windows*" }).name
    }
    process
    {
        # set replicationscope
        switch ($ReplicationScope)
        {
            "Legacy" {$DnsPath = "AD:\DC=$ZoneName,CN=MicrosoftDNS,CN=System,$DomainDN"}
            default {$DnsPath = "AD:\DC=$ZoneName,CN=MicrosoftDNS,DC=$($ReplicationScope)DNSZones,$DomainDN"}
        }

        $DnsEntries = Get-ChildItem -Path $DnsPath

        foreach ($DnsEntry in $DnsEntries)
        {
            $Path = $DnsEntry.PSpath.split("\")[1]
            $Acl = Get-Acl -Path $Path
            $Owner = $Acl.Owner
            $Name = $DnsEntry.Name
            $FullComputerName = "$DomainNB\$Name"
        
            # skip system records and DC SRV records
            if ($Owner -eq "NT AUTHORITY\SYSTEM" -or $Owner -eq "BUILTIN\Administrators"){Continue}
            if ($Path -like "*_msdcs*"){Continue}

            foreach ($DhcpServer in $DhcpServers)
            {
                # orphaned sids or owned by dhcp server
                if($Owner -like "*S-1-5-21-*" -or $Owner -eq "$DomainNB\$DhcpServer$")
                {
                    if ($Computers -contains $Name)
                    {
                        # exclude dhcp servers which own their record
                        if ($Name -ne $DhcpServer)
                        {
                            [pscustomobject]@{
                                Account           = $FullComputerName
                                Record            = $Name
                                State             = "DomainOrphanedOwner"
                                DistinguishedName = $DnsEntry.DistinguishedName
                                Acl               = $Acl
                            }
                            Return
                        }
                    }
                    else
                    {
                        [pscustomobject]@{
                            Account           = $DomainDnsUpdateProxy
                            Record            = $Name
                            State             = "OrphanedOwner"
                            DistinguishedName = $DnsEntry.DistinguishedName
                            Acl               = $Acl
                        }
                        Return
                    }
                }
                elseif ($Owner -eq "$FullComputerName$")
                {
                    # evaluate if the computer account is missing an ACE entry
                    $AdRights = ($Acl.Access | Where-Object { $_.IdentityReference.Value -eq "$FullComputerName$" }).ActiveDirectoryRights

                    if ($AdRights -eq $null)
                    {
                        [pscustomobject]@{
                            Account           = $FullComputerName
                            Record            = $Name
                            State             = "ComputerAceMissing"
                            DistinguishedName = $DnsEntry.DistinguishedName                            
                            Acl               = $Acl
                        }
                        Return
                    }
                }
            }
        }
    }
}

function Reset-BrokenDnsAcls
{
    <# 
    .SYNOPSIS 
        Resets the ownership and ACE for a DNS record, a process required before enabling DNS scavenging. For practical purposes only accepts input from the pipeline. 
    .EXAMPLE 
        Get-BrokenDnsAcl -ZoneName domain.local -DnsUpdateProxy DnsUpdateProxy -DhcpServers server1,server2 | Reset-BrokenDnsAcl 
     
        Resets ACE on records returned by Get-BrokenDnsAcl.
    .PARAMETER Acl 
        A System.DirectoryServices.ActiveDirectorySecurity object.
    .PARAMETER Account 
        Name of a user or computer object to re-assign record permissions.
    #> 

    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param
    (
	[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
	[System.DirectoryServices.ActiveDirectorySecurity]$Acl,

        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
	[string]$Account
    )

    process
    {
        if ($PSCmdlet.ShouldProcess("Edit ACE of $($Acl.Path)?:"))
        {
            # retrieve SID for ACL entry
            $AdObject = New-Object System.Security.Principal.NTAccount("$Account$")
            $Sid = $AdObject.Translate([System.Security.Principal.SecurityIdentifier])

            # generate ACL object
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"                
            $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid,"GenericAll","Allow",$inheritanceType)            

            # path
            $Path = $Acl.Path.Split("\")[1]

            # set ACL object
            $Acl.AddAccessRule($AccessRule)
            $Acl.SetOwner($sid)

            # cleanup orphaned SID entries while here
            $RemoveAccessRules = $Acl.Access | Where-Object { $_.IdentityReference -like "S-1-5-21-*" }
            if ($RemoveAccessRules)
            {
                foreach ($RemoveAccessRule in $RemoveAccessRules)
                {
                    $Acl.RemoveAccessRule($RemoveAccessRule) | Out-Null
                }
            }

            Set-Acl -Path $Path -AclObject $Acl
        }
    }
}
