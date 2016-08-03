
## Log Insight

## Service Composer or DFW.

##EXAMPLE
## NTP Consumers and NTP Providers

## Providers == Servers
## Consumers == Subnets/VMs/DC
## Match on Security Tag is not the best.

#NTP Consumers
#LiAgent Consumers
#
#Windows Client
#Linux Client group


param (

    #protocol
      $t = "tcp",
      $u = "udp",
    #services
    ##web services
      $http = "80",
      $https = "443",
    ##management services
      $securesyslog = "1514",
      $syslog = "514",
      $ntp = "123",
      $ssh = "22",
      $dhcpserver = "67",
      $dhcpclient = "68",
    ##ad services
      $kerberos = "88",
      $ADGlobalCatalogSecure = "3269",
      $ADGlobalCatalog = "3268",
      $AD = "389",
      $ADssl = "636",
    ##Internet services
      $dns = "53",
    ##mail services
      $smtp = "25",
      $smtpsecure = "465",
    ##database services
      $mysql = "1433",
      $cassandraclients = "9042",
      $cassandrareplication = "7000",
      $cassandrathiftclient = "9160",
      $cassandrathriftservice1 = "16520-16580",
      $cassandrathriftservice2 = "59778",
    #vmware specific ports
    ##log insight agents
      $agent="9000",
      $secureagent="9543",
    # Service Groups
    ## Service Group Names
      $WebManagementServiceGroupName = "SVG-Web-Management",
      $LogInsightClusterServiceGroupName = "SVG-Log-Insight-Cluster",
      $LogInsightClusterMasterServiceGroupName = "SVG-Log-Insight-Cluster-Master",
      $SyslogSourcesServiceGroupName = "SVG-Syslog",
      $ActiveDirectoryServiceGroupName = "SVG-Active-Directory",
      $LogInsightAgentServiceGroupName = "SVG-Log-Insight-Agents",
      $SmtpServiceGroupName = "SVG-SMTP",
      $DnsServiceGroupName = "SVG-DNS",
    ##################
    # Security Groups
    ## Providers

      $AdSecurityGroupProviderName = "SG-Provider-ActiveDirectory",
      $DnsSecurityGroupProviderName = "SG-Provider-DNS",
      $SMTPSecurityGroupProviderName = "SG-Provider-SMTP",
      $NTPSecurityGroupProviderName = "SG-Provider-NTP",
      $SyslogSecurityGroupProviderName = "SG-Provider-Syslog",
    # This could be linux and windows management.
      $SshSecurityGroupProviderName = "SG-Provider-SSH",
      $RdpSecurityGroupProviderName = "SG-Provider-RDP",
      $LiAgentSecurityGroupProviderName = "SG-Provider-Log-Insight-Agents",
      $WebManagementSecurityGroupProviderName = "SG-Provider-Web-Management",
      $InternetSecurityGroupProviderName = "SG-Provider-Internet",
      $ICMPSecurityGroupProviderName = "SG-Provider-ICMP",
    ## Consumers
      $AdSecurityGroupConsumerName = "SG-Consumer-ActiveDirectory",
      $DnsSecurityGroupConsumerName = "SG-Consumer-DNS",
      $SMTPSecurityGroupConsumerName = "SG-Consumer-SMTP",
      $NTPSecurityGroupConsumerName = "SG-Consumer-NTP",
      $SyslogSecurityGroupConsumerName = "SG-Consumer-Syslog",
      # This could be linux and windows management.
      $SshSecurityGroupConsumerName = "SG-Consumer-SSH",
      $RdpSecurityGroupConsumerName = "SG-Consumer-RDP",
      $LiAgentSecurityGroupConsumerName = "SG-Consumer-Log-Insight-Agents",
      $WebManagementSecurityGroupConsumerName = "SG-Consumer-Web-Management",
      $InternetSecurityGroupConsumerName = "SG-Consumer-Internet",
      $ICMPSecurityGroupConsumerName = "SG-Consumer-ICMP",

    ## Application
      $vCenterSecurityGroupApplicationName = "SG-vCenter-Appliances",
      $LogInsightSecurityGroupApplicationName = "SG-LogInsight-Cluster",
      $vSphereSecurityGroupApplicationName = "SG-vSphere-Hosts",
      $NSXSecurityGroupApplicationName = "SG-NSX-Components",
      $DNSSecurityGroupApplicationName = "SG-DNS-Servers",
      $ADSecurityGroupApplicationName = "SG-AD-Servers",
      $NTPSecurityGroupApplicationName = "SG-NTP-Servers",
      $SMTPSecurityGroupApplicationName = "SG-SMTP-Servers",

    ##################
    # Security Tags
      $LogInsightSecurityTagName = "ST-LogInsight-Node",
      $vCenterSecurityTagName = "ST-vCenter-Server",
      $NSXSecurityTagName = "ST-NSX-Component",
      $DnsSecurityTagName = "ST-DNS-Server",
      $AdSecurityTagName = "ST-AD-Server",
      $NTPSecurityTagName = "ST-NTP-Server",
      $SMTPSecurityTagName = "ST-SMTP-Server",
    ##############
    # Mandatory IP definitions
      $LogInsightLoadBalancerIPAddress = "192.168.100.95",
      $NsxManagerIPAddress = "",
      $NsxControllerIpAddress = "",

    ##################
    # Firewall Rule Sections
      $LogInsightFirewallSectionName = "Log Insight Cluster",
      $ActiveDirectoryFirewallSectionName = "Active Directory Services",
      $DnsFirewallSectionName = "DNS Services",
      $NtpFirewallSectionName = "NTP Services",
      $SmtpFirewallSectionName = "SMTP Services",
      $vCenterFirewallSectionName = "vCenter Services"


    ##################
    # Firewall Rule Tags
      $LogInsightExternalTag = "LogInsight-External",
      $LogInsightClusterTag = "LogInsight-Cluster",
      $LogInsightDenyTag = "LogInsight-Deny",
    ##############
    # Firewall Rule Names
      $FirewallRuleClusterName = "FW-LogInsight-Cluster",
      $FirewallRuleManagementName = "FW-LogInsight-Management",
      $FirewallRuleExternalName = "FW-LogInsight-External",
    ##################
    # IP Sets
      $LogInsightIlbName = "IP-LogInsight-VIP",
    )

  ##################
  # SERVICES
  # Creating Web Services
  ##http
  $tcp80 = Get-NsxService "$t-$http"
   if (!$tcp80)
  {
    $tcp80 = (New-NsxService -name "$t-$http" -protocol $t -port $Http -description "HTTP")
  }
  #HTTPS
  $tcp443 = Get-NsxService "$t-$https"
   if (!$tcp443)
  {
    $tcp443 = (New-NsxService -name "$t-$https" -protocol $t -port $Https -description "HTTPS")
  }

  # Creating Management Services
  ## smtp
  $tcp25 = Get-NsxService "$t-$smtp"
   if (!$tcp25)
  {
    $tcp25 = (New-NsxService -name "$t-$smtp" -protocol $t -port $smtp -description "SMTP")
  }
  $tcp465 = Get-NsxService "$t-$smtpsecure"
   if (!$tcp465)
  {
    $tcp465 = (New-NsxService -name "$t-$smtpsecure" -protocol $t -port $smtpsecure -description "Secure SMTP")
  }

  ##Syslog UDP
  $udp514 = Get-NsxService "$u-$Syslog"
   if (!$udp514)
  {
    $udp514 = (New-NsxService -name "$u-$Syslog" -protocol $u -port $Syslog -description "Syslog over UDP")
  }
  ##Syslog TCP
  $tcp514 = Get-NsxService "$t-$Syslog"
   if (!$tcp514)
  {
    $tcp514 = (New-NsxService -name "$t-$Syslog" -protocol $t -port $Syslog -description "Syslog over TCP")
  }
  ##Secure Syslog TCP
  $tcp1514 = Get-NsxService "$t-$Syslog"
     if (!$tcp1514)
    {
      $tcp1514 = (New-NsxService -name "$t-$Syslog" -protocol $t -port $Syslog -description "Secure Syslog over TCP")
    }
  ## NTP
  $udp123 = Get-NsxService "$u-$ntp"
     if (!$udp123)
    {
      $udp123 = (New-NsxService -name "$u-$ntp" -protocol $u -port $ntp -description "NTP")
    }
  ##SSH
  $tcp22 = Get-NsxService "$t-$Ssh"
     if (!$tcp22)
    {
      $tcp22 = (New-NsxService -name "$t-$Ssh" -protocol $t -port $Ssh -description "Syslog over TCP")
    }


  #dns
  $tcp53 = Get-NsxService "$t-$dns"
    if (!$tcp53)
    {
      $tcp53 = (New-NsxService -name "$t-$dns" -protocol $t -port $dns -description "DNS - TCP")
    }
  $udp53 = Get-NsxService "$u-$dns"
    if (!$udp53)
    {
      $udp53 = (New-NsxService -name "$u-$dns" -protocol $u -port $dns -description "DNS - UDP")
    }

  #dhcp services
  $udp67 = Get-NsxService "$u-$dhcpserver"
    if (!$udp67)
    {
      $udp67 = New-NsxService -name "$u-$dhcpserver" -Protocol $u -port $dhcpserver -description "DHCP Server"
    }
  $udp68 = Get-NsxService "$u-$dhcpclient"
    if (!$udp68)
    {
      $udp68= New-NsxService -name "$u-$dhcpclient" -Protocol $u -port $dhcpclient -description "DHCP Client"
    }

  #Active Directory
  $tcp88 = Get-NsxService "$t-$kerberos"
    if (!$tcp88)
    {
      $tcp88 = (New-NsxService -name "$t-$kerberos" -protocol $t -port $Kerberos -description "Kerberos - TCP")
    }
  $udp88 = Get-NsxService "$u-$kerberos"
    if (!$udp88)
    {
      $udp88 = (New-NsxService -name "$u-$kerberos" -protocol $u -port $kerberos -description "Kerberos - UDP")
    }
  $tcp389 = Get-NsxService "$t-$ad"
    if (!$tcp389)
    {
      $tcp389 = (New-NsxService -name "$t-$ad" -protocol $t -port $ad -description "Active Directory - TCP")
    }
  $udp389 = Get-NsxService "$u-$ad"
    if (!$udp389)
    {
      $udp389 = (New-NsxService -name "$u-$ad" -protocol $u -port $ad -description "Active Directory - UDP")
    }
  $tcp636 = Get-NsxService "$t-$ADssl"
    if (!$tcp636)
    {
      $tcp636 = (New-NsxService -name "$t-$ADssl" -protocol $t -port $ADssl -description "Active Directory SSL")
    }
  $tcp3268 = Get-NsxService "$t-$ADGlobalCatalog"
    if (!$tcp3268)
    {
      $tcp3268 = (New-NsxService -name "$t-$ADGlobalCatalog" -protocol $t -port $ADGlobalCatalog -description "Active Directory Global Catalog")
    }
  $tcp3269 = Get-NsxService "$t-$ADGlobalCatalogSecure"
    if (!$tcp3269)
    {
      $tcp3269 = (New-NsxService -name "$t-$ADGlobalCatalogSecure" -protocol $t -port $ADGlobalCatalogSecure -description "Active Directory Global Catalog - Secure")
    }
  #Creating Database Services
  ## MySQL
  $tcp1433 = Get-NsxService "$t-$mysql"
     if (!$tcp1433)
     {
      $tcp1433 = (New-NsxService -name "$t-$mysql" -protocol $t -port $mysql -description "MySQL")
     }
  ## Cassandra
  $tcp7000 = Get-NsxService "$t-$cassandrareplication"
     if (!$tcp7000)
     {
       $tcp7000 = (New-NsxService -name "$t-$cassandrareplication" -protocol $t -port $cassandrareplication -description "Cassandra Replication")
     }
  $tcp9042 = Get-NsxService "$t-$cassandrathiftclient"
     if (!$tcp9042)
     {
      $tcp9042 = (New-NsxService -name "$t-$cassandraclients" -protocol $t -port $cassandraclients -description "Cassandra Native Clients")
     }
  $tcp9160 = Get-NsxService "$t-$cassandrathiftclient"
      if (!$tcp9160)
      {
       $tcp9160 = (New-NsxService -name "$t-$cassandrathiftclient" -protocol $t -port $cassandrathiftclient -description "Cassandra Thrift Clients")
      }
  $tcp16520range = Get-NsxService "$t-$cassandrathriftservice1"
      if (!$tcp16520range)
      {
       $tcp16520range = (New-NsxService -name "$t-$cassandrathriftservice1" -protocol $t -port $cassandrathriftservice1 -description "Cassandra Thrift service range")
      }
  $tcp59778 = Get-NsxService "$t-$cassandrathriftservice2"
      if (!$tcp59778)
      {
       $tcp59778 = (New-NsxService -name "$t-$cassandrathriftservice2" -protocol $t -port "$cassandrathriftservice2" -description "Cassandra Thrift service port")
      }

  #VMware specific
  ## log insight specific
  $tcp9000 = Get-NsxService "$t-$agent"
     if (!$tcp9000)
     {
      $tcp9000 = (New-NsxService -name "$t-$agent" -protocol $t -port $agent -description "Log Insight agent")
     }
  $tcp9543 = Get-NsxService "$t-$secureagent"
    if (!$tcp9543)
    {
     $tcp9543 = (New-NsxService -name "$t-$secureagent" -protocol $t -port $secureagent -description "Log Insight secure agent")
    }


# Creating Service Groups

## Web management
  $WebManagementServiceGroup = New-NsxServiceGroup $WebManagementServiceGroupName -description "Web Services"
  $WebManagementServiceGroup | New-NsxServiceGroupMember -member $tcp80,$tcp443

## Active Directory
  $ActiveDirectoryServiceGroup = New-NsxServiceGroup $ActiveDirectoryServiceGroupName -description "Active Directory services"
  $ActiveDirectoryServiceGroup | New-NsxServiceGroupMember -member $tcp389,$udp389,$tcp88,$udp88,$tcp3268,$tcp3269

## SMTP

  $SmtpServiceGroupName = New-NsxServiceGroup $SmtpServicegroupName -description "SMTP Services"
  $SmtpServiceGroupName | New-NsxServiceGroupMember -member $tcp25,$tcp465

## DNS

  $DnsServiceGroup = New-NsxServiceGroup $DnsServiceGroupName -description "DNS tcp and udp"
  $DnsServiceGroup | New-NsxServiceGroupMember -member $udp53,$tcp53

## NTP

  # Single Service. No service group needs to be made.


## Log Insight specfic
  ## Log Insight Cluster group
  $LogInsightClusterServiceGroup = New-NsxServiceGroup $LogInsightClusterServiceGroupName -description "Cluster replication ports"
  $LogInsightClusterServiceGroup | New-NsxServiceGroupMember -member $tcp7000,$tcp9042,$tcp9160,$tcp59778,$tcp16520range
  ## Log Insight master cluster group
  $LogInsightClusterMasterServiceGroup = New-NsxServiceGroup $LogInsightClusterMasterServiceGroupName
  $LogInsightClusterMasterServiceGroup | New-NsxServiceGroupMember -member $WebManagementServiceGroup, $LogInsightClusterServicegroup, $ActiveDirectoryServiceGroup, $DnsServiceGroup




#MySQL


#DHCP

##################
# SECURITY TAGS
# Creating Security Tags

  $LogInsightSecurityTag= New-NsxSecurityTag -name "$LogInsightSecurityTagName"
  $vCenterSecurityTag = New-NsxSecurityTag -name "$vCenterSecurityTagName"
  $NSXSecurityTag = New-NsxSecurityTag -name "$NSXSecurityTagName"
  $DnsSecurityTag = New-NsxSecurityTag -name "$DnsSecurityTagName"
  $AdSecurityTag = New-NsxSecurityTag -name "$AdSecurityTagName"
  $NTPSecurityTag = New-NsxSecurityTag -name "$NTPSecurityTagName"
  $SMTPSecurityTag = New-NsxSecurityTag -name "$SMTPSecurityTagName"


##################
# CREATING SECURITY GROUPS
# Providers


  $AdSecurityGroupProvider = New-NsxSecurityGroup -name "$AdSecurityGroupProviderName" -description "Active Directory Provider Security Group"
  $DnsSecurityGroupProvider = New-NsxSecurityGroup -name "$DnsSecurityGroupProviderName" -description "DNS Provider Security Group"
  $SMTPSecurityGroupProvider = New-NsxSecurityGroup -name "$SMTPSecurityGroupProviderName" -description "SMTP Provider Security Group"
  $SyslogSecurityGroupProvider = New-NsxSecurityGroup -name "$DnsSecurityGroupProviderName" -description "Syslog Provider Security Group"
  $NTPSecurityGroupProvider = New-NsxSecurityGroup -name "$NTPSecurityGroupProviderName" -description "NTP Provider Security Group"
  $SSHSecurityGroupProvider = New-NsxSecurityGroup -name "$SSHSecurityGroupProviderName" -description "SSH Provider Security Group"
  $RdpSecurityGroupProvider = New-NsxSecurityGroup -name "$RdpSecurityGroupProviderName" -description "Rdp Provider Security Group"
  $LiAgentSecurityGroupProvider = New-NsxSecurityGroup -name "$LiAgentSecurityGroupProviderName" -description "LiAgent Provider Security Group"
  $WebManagementSecurityGroupProvider = New-NsxSecurityGroup -name "$WebManagementSecurityGroupProviderName" -description "WebManagement Provider Security Group"
  $InternetSecurityGroupProvider = New-NsxSecurityGroup -name "$InternetSecurityGroupProviderName" -description "Internet Provider Security Group"
  $ICMPSecurityGroupProvider = New-NsxSecurityGroup -name "$ICMPSecurityGroupProviderName" -description "ICMP Provider Security Group"


# Consumers

  $AdSecurityGroupConsumer = New-NsxSecurityGroup -name "$AdSecurityGroupConsumerName" -description "Active Directory Consumer Security Group"
  $DnsSecurityGroupConsumer = New-NsxSecurityGroup -name "$DnsSecurityGroupConsumerName" -description "DNS Consumer Security Group"
  $SMTPSecurityGroupConsumer = New-NsxSecurityGroup -name "$SMTPSecurityGroupConsumerName" -description "SMTP Consumer Security Group"
  $SyslogSecurityGroupConsumer = New-NsxSecurityGroup -name "$DnsSecurityGroupConsumerName" -description "Syslog Consumer Security Group"
  $NTPSecurityGroupConsumer = New-NsxSecurityGroup -name "$NTPSecurityGroupConsumerName" -description "NTP Consumer Security Group"
  $SSHSecurityGroupConsumer = New-NsxSecurityGroup -name "$SSHSecurityGroupConsumerName" -description "SSH Consumer Security Group"
  $RdpSecurityGroupConsumer = New-NsxSecurityGroup -name "$RdpSecurityGroupConsumerName" -description "Rdp Consumer Security Group"
  $LiAgentSecurityGroupConsumer = New-NsxSecurityGroup -name "$LiAgentSecurityGroupConsumerName" -description "LiAgent Consumer Security Group"
  $WebManagementSecurityGroupConsumer = New-NsxSecurityGroup -name "$WebManagementSecurityGroupConsumerName" -description "WebManagement Consumer Security Group"
  $InternetSecurityGroupConsumer = New-NsxSecurityGroup -name "$InternetSecurityGroupConsumerName" -description "Internet Consumer Security Group"
  $ICMPSecurityGroupConsumer = New-NsxSecurityGroup -name "$ICMPSecurityGroupConsumerName" -description "ICMP Consumer Security Group"

# Applications
## Log Insight

  $LogInsightSecurityGroupApplication = New-NsxSecurityGroup -name "$LogInsightSecurityGroupApplicationName" -description "Log Insight Cluster Security Group" -includemember $LogInsightSecurityTag
  $vCenterSecurityGroupApplication = New-NsxSecurityGroup -name "$LogInsightSecurityGroupApplicationName" -description "vCenter Security Group" -includemember $vCenterSecurityTag
  $vSphereSecurityGroupApplication = New-NsxSecurityGroup -name "$vSphereSecurityGroupApplicationName" -description "vSphere Security Group"
  $NSXSecurityGroupApplication = New-NsxSecurityGroup -name "$NSXSecurityGroupApplicationName" -description "NSX Manager and Controllers Security group" -includemember $NSXSecurityTag
  $DNSSecurityGroupApplication = New-NsxSecurityGroup -name "$DNSSecurityGroupApplicationName" -description "DNS Server Security Group" -includemember $DnsSecurityTag
  $ADSecurityGroupApplication = New-NsxSecurityGroup -name "$ADSecurityGroupApplicationName" -description "Active Directory Server Security Group" -includemember $AdSecurityTag
  $NTPSecurityGroupApplication = New-NsxSecurityGroup -name "$NTPSecurityGroupApplicationName" -description "NTP Server Security Group" -includemember $NTPSecurityTag
  $SMTPSecurityGroupApplication = New-NsxSecurityGroup -name "$SMTPSecurityGroupApplicationName" -description "SMTP Server Security Group" -includemember $SMTPSecurityTag


##################
# FIREWALL SECTIONS
# Creating Sections

  $LogInsightFirewallSection = New-NsxFirewallSection -name "$LogInsightFirewallSectionName"
  $ActiveDirectoryFirewallSection =  New-NsxFirewallSection -name "$ActiveDirectoryFirewallSectionName"
  $DnsFirewallSection =  New-NsxFirewallSection -name "$DnsFirewallSectionName"
  $NtpFirewallSection =  New-NsxFirewallSection -name "$NtpFirewallSectionName"
  $SmtpFirewallSection =  New-NsxFirewallSection -name "$SmtpFirewallSectionName"
  $vCenterFirewallSection =  New-NsxFirewallSection -name "$vCenterFirewallSectionName"

##################
# FIREWALL RULES


# DNS Servers

  $DnsFirewallSection | New-NsxFirewallRule -name "DNS Provider to Consumer" -source $DnsSecurityGroupProvider -destination $DnsSecurityGroupConsumer -service $DnsServiceGroup -Action "allow" -AppliedTo $DnsSecurityGroupProvider,$DnsSecurityGroupConsumer

  $DnsFirewallSection | New-NsxFirewallRule -name "DNS Consumer to Provider" -source $DnsSecurityGroupConsumer -destination $DnsSecurityGroupProvider -service $DnsServiceGroup -Action "allow" -AppliedTo $DnsSecurityGroupProvider,$DnsSecurityGroupConsumer
