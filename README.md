# DnsScavengingPrep
Tools to fix orphaned DNS records before enabling DNS scavenging. Requires a DnsUpdateProxy user account has been provisioned. These cmdlets can return a list of records as well as remediate. The purpose of this module is to reassign ACL permissions to the DnsUpdateProxy user or computer accounts, as appropriate. The DhcpServers parameter is used to search for records owned by one or more DHCP server accounts. This is typical of an environment where DnsUpdateProxy credentials are recently implemented.

# Usage
Return a list of all records that would be modified in both forward and reverse zones, limits the search to valid zones for scavenging.

```
Get-DnsZonesForAclCheck | Get-BrokenDnsAcls -DhcpServers dhcp1 -DnsUpdateProxy DnsUpdateProxyUser
```

Reset the ACLs of every record returned. It also will strip orphaned SIDs from every object returned by Get-BrokenDnsAcls.

```
Get-DnsZonesForAclCheck | Get-BrokenDnsAcls -DhcpServers dhcp1 -DnsUpdateProxy DnsUpdateProxyUser | Reset-BrokenDnsAcls -Confirm:$false
```
