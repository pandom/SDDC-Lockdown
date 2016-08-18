
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

    ##################
    # Service Groups
      $LogInsightMasterServiceGroupName = "SVG-Log-Insight-Cluster-Master",
      $ManagementServiceGroupName = "SVG-SDDC-Management",
      $LogInsightClusterServiceGroupName = "SVG-Log-Insight-Cluster",
      $SyslogSourcesServiceGroupName = "SVG-Syslog",
      $ActiveDirectoryServiceGroupName = "SVG-Active-Directory",
      $LogInsightAgentServiceGroupName = "SVG-Log-Insight-Agents",
      $SmtpServiceGroupName = "SVG-SMTP",
      $DnsServiceGroupName = "SVG-DNS",
      $DHCPServiceGroupName = "SVG-DHCP",
    ##################
    # Security Groups
    #AD
      $AdSecurityGroupProviderName = "SG-Provider-ActiveDirectory",
      $AdSecurityGroupConsumerName = "SG-Consumer-ActiveDirectory",
      $ADSecurityGroupApplicationName = "SG-AD-Servers",
    #DNS
      $DnsSecurityGroupProviderName = "SG-Provider-DNS",
      $DnsSecurityGroupConsumerName = "SG-Consumer-DNS",
      $DNSSecurityGroupApplicationName = "SG-DNS-Servers",
    #SMTP
      $SMTPSecurityGroupProviderName = "SG-Provider-SMTP",
      $SMTPSecurityGroupConsumerName = "SG-Consumer-SMTP",
      $SMTPSecurityGroupApplicationName = "SG-SMTP-Servers",
    #NTP
      $NTPSecurityGroupProviderName = "SG-Provider-NTP",
      $NTPSecurityGroupConsumerName = "SG-Consumer-NTP",
      $NTPSecurityGroupApplicationName = "SG-NTP-Servers",
    #Syslog
      $SyslogSecurityGroupProviderName = "SG-Provider-Syslog",
      $SyslogSecurityGroupConsumerName = "SG-Consumer-Syslog",
      $LogInsightSecurityGroupApplicationName = "SG-LogInsight-Cluster",
    #DHCP
      $DHCPSecurityGroupProviderName = "SG-Provider-DHCP",
      $DHCPSecurityGroupConsumerName = "SG-Consumer-DHCP",
      $DHCPSecurityGroupApplicationName = "SG-DHCP-Servers",
    #vCenter
      $vCenterSecuritygroupProviderName = "SG-Provider-vCenter",
      $vCenterSecurityGroupConsumerName = "SG-Consumer-vCenter",
      $vCenterSecurityGroupApplicationName = "SG-vCenter-Appliances",
    #NSX
      $NSXSecurityGroupProviderName = "SG-Provider-NSX",
      $NSXSecurityGroupConsumerName = "SG-Consumer-NSX",
      $NSXSecurityGroupApplicationName = "SG-NSX-Components",
    #Odds and ends
      $vSphereSecurityGroupApplicationName = "SG-vSphere-Hosts",
      $WindowsCorporateSecurityGroupName = "SG-Windows-Corporate",
      $LinuxCorporateSecurityGroupName = "SG-Linux-Corporate",
    #Management - internal
      $SDDCManagementInternalSecurityGroupApplicationName = "SG-SDDC-Management-Internal",
    #Management - external
      $ManagementVPNSecurityGroupApplicationName = "SG-SDDC-Management-VPN",
    #Internal Web
      $InternalWebSecurityGroupProviderName = "SG-Provider-Internal-Web",
      $InternalWebSecurityGroupConsumerName = "SG-Consumer-Internal-Web",
    #Internal SSH
      $InternalSSHSecurityGroupProviderName = "SG-Provider-Internal-SSH",
      $InternalSSHSecurityGroupConsumerName = "SG-Consumer-Internal-SSH",
    #Internal RDP
      $InternalRDPSecurityGroupProviderName = "SG-Provider-Internal-RDP",
      $InternalRDPSecurityGroupConsumerName = "SG-Consumer-Internal-RDP",
    ##################
    # Security Tags
    ## Applications

      $LogInsightSecurityTagName = "ST-Log-Insight-Cluster",
      $vCenterSecurityTagName = "ST-vCenter-Servers",
      $NSXSecurityTagName = "ST-NSX-Components",
      $DnsSecurityTagName = "ST-DNS-Servers",
      $AdSecurityTagName = "ST-AD-Servers",
      $NTPSecurityTagName = "ST-NTP-Servers",
      $SMTPSecurityTagName = "ST-SMTP-Servers",
      $LinuxCorporateSecurityTagName = "ST-Linux-Corporate",
      $WindowsCorporateSecurityTagName = "ST-Windows-Corporate",
      $SDDCManagementSecurityTagName = "ST-SDDC-Management-Internal",
      $DHCPSecurityTagName = "ST-DHCP-Servers",
      $ManagementInternalSecurityTagName = "ST-SDDC-Management-Internal",



    ##############
    # Mandatory IP definitions
      $LogInsightLoadBalancerIPAddress = "192.168.100.95",
      $NsxManagerIPAddress = "192.168.100.201",
      $NsxControllerIpAddress1 = "192.168.100.202",
      $NsxControllerIpAddress2 = "192.168.100.203",
      $NsxControllerIpAddress3 = "192.168.100.204",

    ##################
    # Miscellaneous
    # Firewall Rule Sections
      $LogInsightFirewallSectionName = "Log Insight Cluster",
      $ActiveDirectoryFirewallSectionName = "Active Directory Services",
      $DnsFirewallSectionName = "DNS Services",
      $NtpFirewallSectionName = "NTP Services",
      $SmtpFirewallSectionName = "SMTP Services",
      $vCenterFirewallSectionName = "vCenter Services",
      $RDPFirewallSectionName = "Management - RDP Services",
      $SSHFirewalLSectionName = "Management - SSH Services",
      $WebFirewallSectionName = "Management - Web Services",
      $SDDCInternalManagementFirewallSectionName = "SDDC Internal Management",
      $SDDCVPNManagementFirewallSectionName = "SDDC VPN Management",
      $SDDCExternalManagementFirewallSectionName = "SDDC External Management",

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


    ##################
    # Services
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
        $rdp = "3389",
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
      ##clustering
        $cassandraclients = "9042",
        $cassandrareplication = "7000",
        $cassandrathiftclient = "9160",
        $cassandrathriftservice1 = "16520-16580",
        $cassandrathriftservice2 = "59778",
      #vmware specific ports
      ##log insight agents
        $agent="9000",
        $secureagent="9543"
    )

  write-host -foregroundcolor green "Paramters defined"
  ##################
  # SERVICES
  # Creating Web Services
  write-host -foregroundcolor green "Creating Services"
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
  $tcp1514 = Get-NsxService "$t-$securesyslog"
     if (!$tcp1514)
    {
      $tcp1514 = (New-NsxService -name "$t-$securesyslog" -protocol $t -port $securesyslog -description "Secure Syslog over TCP")
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
      $tcp22 = (New-NsxService -name "$t-$Ssh" -protocol $t -port $Ssh -description "SSH protocol")
    }
  ##SSH
  $tcp3389 = Get-NsxService "$t-$rdp"
     if (!$tcp3389)
    {
      $tcp3389 = (New-NsxService -name "$t-$rdp" -protocol $t -port $rdp -description "Remote Desktop Protocol")
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

write-host -foregroundcolor green "Creating Service Groups"

## Web management
  $ManagementServiceGroup = Get-NsxServicegroup "$ManagementServiceGroupName"
    if (!$ManagementServiceGroup)
    {
      $ManagementServiceGroup = New-NsxServiceGroup $ManagementServiceGroupName -description "Web and SSH Management services"
      $ManagementServiceGroup | Add-NsxServiceGroupMember -member $tcp80,$tcp443
    }


## Active Directory
  $ActiveDirectoryServiceGroup = New-NsxServiceGroup $ActiveDirectoryServiceGroupName -description "Active Directory services"
  $ActiveDirectoryServiceGroup | Add-NsxServiceGroupMember -member $tcp389,$udp389,$tcp88,$udp88,$tcp3268,$tcp3269

## SMTP

  $SmtpServiceGroup = New-NsxServiceGroup $SmtpServicegroupName -description "SMTP Services"
  $SmtpServiceGroup | Add-NsxServiceGroupMember -member $tcp25,$tcp465

## DNS

  $DnsServiceGroup = New-NsxServiceGroup $DnsServiceGroupName -description "DNS tcp and udp"
  $DnsServiceGroup | Add-NsxServiceGroupMember -member $udp53,$tcp53

## Syslog
  $SyslogServiceGroup = New-NsxServiceGroup $SyslogSourcesServiceGroupName -description "Syslog tcp/udp and Secure Syslog"
  $SyslogServiceGroup | Add-NsxServiceGroupMember -member $udp514,$tcp514,$tcp1514


##DHCP

  $DHCPServiceGroup = New-NsxServiceGroup $DHCPServiceGroupName -description "DHCP ports"
  $DHCPServiceGroup | Add-NsxServiceGroupMember -member $udp68,$udp67


## Log Insight specfic
  ## Log Insight Cluster group
  $LogInsightClusterServiceGroup = New-NsxServiceGroup $LogInsightClusterServiceGroupName -description "Cluster replication ports"
  $LogInsightClusterServiceGroup | Add-NsxServiceGroupMember -member $tcp7000,$tcp9042,$tcp9160,$tcp59778,$tcp16520range

  $LogInsightMasterServiceGroup = New-NsxServiceGroup $LogInsightMasterServiceGroupName -description "All services replicated through Log Insight cluster"
  $LogInsightMasterServiceGroup | Add-NsxServiceGroupMember -member $LogInsightClusterServiceGroup,$SyslogServicegroup,$DnsServiceGroup,$SmtpServiceGroup,$ManagementServiceGroup,$ActiveDirectoryServiceGroup


write-host -foregroundcolor green "Creating Security Tags"
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
  $SDDCManagementSecurityTag = New-NsxSecurityTag -name "$SDDCManagementSecurityTagName"
  $WindowsCorporateSecurityTag = New-NsxSecurityTag -name "$WindowsCorporateSecurityTagName"
  $LinuxCorporateSecurityTag = New-NsxSecurityTag -name "$LinuxCorporateSecurityTagName"
  $DHCPSecurityTag = New-NsxSecurityTag -name "$DHCPSecurityTagName"



##################
# CREATING SECURITY GROUPS

write-host -foregroundcolor green "Creating  Application SGs"
# Applications Groups

  #LogInsight
  $LogInsightSecurityGroupApplication = New-NsxSecurityGroup -name "$LogInsightSecurityGroupApplicationName" -description "Log Insight Cluster Security Group" -includemember $LogInsightSecurityTag
  #vCenter
  $vCenterSecurityGroupApplication = New-NsxSecurityGroup -name "$vCenterSecurityGroupApplicationName" -description "vCenter Server Security Group" -includemember $vCenterSecurityTag
  #vSphere
  $vSphereSecurityGroupApplication = New-NsxSecurityGroup -name "$vSphereSecurityGroupApplicationName" -description "vSphere Hosts Security Group"
  #NSX
  $NSXSecurityGroupApplication = New-NsxSecurityGroup -name "$NSXSecurityGroupApplicationName" -description "NSX Manager and Controllers Security group" -includemember $NSXSecurityTag
  #DNS
  $DNSSecurityGroupApplication = New-NsxSecurityGroup -name "$DNSSecurityGroupApplicationName" -description "DNS Server Security Group" -includemember $DnsSecurityTag
  #Active Directory
  $ADSecurityGroupApplication = New-NsxSecurityGroup -name "$ADSecurityGroupApplicationName" -description "Active Directory Server Security Group" -includemember $AdSecurityTag
  #NTP
  $NTPSecurityGroupApplication = New-NsxSecurityGroup -name "$NTPSecurityGroupApplicationName" -description "NTP Server Security Group" -includemember $NTPSecurityTag
  #SMTP
  $SMTPSecurityGroupApplication = New-NsxSecurityGroup -name "$SMTPSecurityGroupApplicationName" -description "SMTP Server Security Group" -includemember $SMTPSecurityTag
  #DHCP
  $DHCPSecurityGroupApplication = New-NsxSecurityGroup -name "$DHCPSecurityGroupApplicationName" -description "DHCP Server Security Group" -includemember $DHCPSecurityTag
  #Management
  $SDDCManagementInternalSecurityGroupApplication = New-NsxSecurityGroup -name "$SDDCManagementInternalSecurityGroupApplicationName" -description "Management Host Security Group" -includemember $SDDCManagementSecurityTag

write-host -foregroundcolor green "Creating OS SGs"

# OS Flavor groups

  $WindowsCorporateSecurityGroup = New-NsxSecurityGroup -name "$WindowsCorporateSecurityGroupName" -description "Windows OS Corporate Security Group" -includemember $WindowsCorporateSecurityTag,$ADSecurityGroupApplication,$DNSSecurityGroupApplication,$NTPSecurityGroupApplication,$SMTPSecurityGroupApplication,$DHCPSecurityGroupApplication,$SDDCManagementInternalSecurityGroupApplication

  $LinuxCorporateSecurityGroup = New-NsxSecurityGroup -name "$LinuxCorporateSecurityGroupName" -description "Linux OS Corporate Security Group" -includemember $LogInsightSecurityTag,$LogInsightSecurityGroupApplication,$SDDCManagementInternalSecurityGroupApplication,$vSphereSecurityGroupApplication

# Providers


  $AdSecurityGroupProvider = New-NsxSecurityGroup -name "$AdSecurityGroupProviderName" -description "Active Directory Provider Security Group" -includemember $ADSecurityGroupApplication
  $DnsSecurityGroupProvider = New-NsxSecurityGroup -name "$DnsSecurityGroupProviderName" -description "DNS Provider Security Group" -includemember $DNSSecurityGroupApplication
  $SMTPSecurityGroupProvider = New-NsxSecurityGroup -name "$SMTPSecurityGroupProviderName" -description "SMTP Provider Security Group" -includemember $SMTPSecurityGroupApplication
  $SyslogSecurityGroupProvider = New-NsxSecurityGroup -name "$SyslogSecurityGroupProviderName" -description "Syslog Provider Security Group" -includemember $LogInsightSecurityGroupApplication
  $NTPSecurityGroupProvider = New-NsxSecurityGroup -name "$NTPSecurityGroupProviderName" -description "NTP Provider Security Group" -includemember $NTPSecurityGroupApplication
  $InternalRdpSecurityGroupProvider = New-NsxSecurityGroup -name "$InternalRdpSecurityGroupProviderName" -description "RDP Internal Provider Security Group"
  $InternalSSHSecurityGroupProvider = New-NsxSecurityGroup -name "$InternalSSHSecurityGroupProviderName" -description "SSH Internal Provider Security Group"
  $InternalWebSecurityGroupProvider = New-NsxSecurityGroup -name "$InternalWebSecurityGroupProviderName" -description "Web Internal Provider Security Group"

write-host -foregroundcolor green "Creating Consumer SGs"

# Consumers

  $AdSecurityGroupConsumer = New-NsxSecurityGroup -name "$AdSecurityGroupConsumerName" -description "Active Directory Consumer Security Group" -includemember $LogInsightSecurityGroupApplication
  $DnsSecurityGroupConsumer = New-NsxSecurityGroup -name "$DnsSecurityGroupConsumerName" -description "DNS Consumer Security Group" -includemember $LogInsightSecurityGroupApplication
  $SMTPSecurityGroupConsumer = New-NsxSecurityGroup -name "$SMTPSecurityGroupConsumerName" -description "SMTP Consumer Security Group" -includemember $LogInsightSecurityGroupApplication
  $SyslogSecurityGroupConsumer = New-NsxSecurityGroup -name "$SyslogSecurityGroupConsumerName" -description "Syslog Consumer Security Group"
  $NTPSecurityGroupConsumer = New-NsxSecurityGroup -name "$NTPSecurityGroupConsumerName" -description "NTP Consumer Security Group" -includemember $LogInsightSecurityGroupApplication
  # SDDC INTERNAL MANAGEMENT STACK
  $InternalRDPSecurityGroupConsumer = New-NsxSecurityGroup -name "$InternalRDPSecurityGroupConsumerName" -description "RDP Internal Consumer Security Group" -includemember $SDDCManagementInternalSecurityGroupApplication
  $InternalSSHSecurityGroupConsumer = New-NsxSecurityGroup -name "$InternalSSHSecurityGroupConsumerName" -description "SSH Internal Consumer Security Group" -includemember $SDDCManagementInternalSecurityGroupApplication
  $InternalWebSecurityGroupConsumer = New-NsxSecurityGroup -name "$InternalWebSecurityGroupConsumerName" -description "WEB Internal Consumer Security Group"

write-host -foregroundcolor green "Creating Firewall Rules"

##################
# FIREWALL RULES AND SECTIONS


    #DNS Rule and Section
    #DNS DFW Section
    New-NsxFirewallSection -name "$DnsFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $DnsFirewallSectionName | New-NsxFirewallRule -name "DNS Provider to Consumer" -source $DnsSecurityGroupProvider -destination $DnsSecurityGroupConsumer -service $DnsServiceGroup -Action "allow" -AppliedTo $DnsSecurityGroupProvider,$DnsSecurityGroupConsumer | out-null
    #Consumer to Provider rule
    Get-NsxFirewalLSection $DnsFirewallSectionName | New-NsxFirewallRule -name "DNS Consumer to Provider" -source $DnsSecurityGroupConsumer -destination $DnsSecurityGroupProvider -service $DnsServiceGroup -Action "allow" -AppliedTo $DnsSecurityGroupProvider,$DnsSecurityGroupConsumer | out-null

    #Syslog
    #Syslog DFW Section
    New-NsxFirewallSection -name "$LogInsightFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewalLSection $LogInsightFirewallSectionName  | New-NsxFirewallRule -name "Syslog Provider to Consumer" -source $SyslogSecurityGroupProvider -destination $SyslogSecurityGroupConsumer -service $SyslogServiceGroup -Action "allow" -AppliedTo $SyslogSecurityGroupConsumer,$SyslogSecurityGroupProvider | out-null
    #Consumer to Provider rule
    Get-NsxFirewalLSection $LogInsightFirewallSectionName  | New-NsxFirewallRule -name "Syslog Consumer to Provider" -source $SyslogSecurityGroupConsumer -destination $SyslogSecurityGroupProvider -service $SyslogServicegroup -Action "allow" -AppliedTo $SyslogSecurityGroupConsumer,$SyslogSecurityGroupProvider | out-null
    #Intra-Cluster communication
    Get-NsxFirewalLSection $LogInsightFirewallSectionName  | New-NsxFirewallRule -name "Log Insight Node" -source $LogInsightSecurityGroupApplication -destination $LogInsightSecurityGroupApplication -service $LogInsightMasterServiceGroup -Action "allow" -AppliedTo $LogInsightSecurityGroupApplication | out-null


    #NTP
    #NTP DFW Section
    New-NsxFirewallSection -name "$NtpFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $NtpFirewallSectionName | New-NsxFirewallRule -name "NTP Provider to Consumer" -source $NTPSecurityGroupProvider -destination $NTPSecurityGroupConsumer -service $udp123 -action "allow" -AppliedTo $NTPSecurityGroupProvider,$NTPSecurityGroupConsumer | out-null
    #Consumer to Provider rule
    Get-NsxFirewallSection $NtpFirewallSectionName | New-NsxFirewallRule -name "NTP Consumer to Provider" -source $NTPSecurityGroupConsumer -destination $NTPSecurityGroupProvider -service $udp123 -action "allow" -AppliedTo $NTPSecurityGroupProvider,$NTPSecurityGroupConsumer | out-null
    #SMTP
    #SMTP DFW Section
    New-NsxFirewallSection -name "$SmtpFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $SmtpFirewallSectionName | New-NsxFirewallRule -name "SMTP Provider to Consumer" -source $SMTPSecurityGroupProvider -destination $SMTPSecurityGroupConsumer -service $SmtpServiceGroup -action "allow" -AppliedTo $SMTPSecurityGroupProvider,$SMTPSecurityGroupConsumer | out-null
    #Consumer to Provider rule
    Get-NsxFirewallSection $SmtpFirewallSectionName | New-NsxFirewallRule -name "SMTP Consumer to Provider" -source $SMTPSecurityGroupConsumer -destination $SMTPSecurityGroupProvider -service $SmtpServiceGroup -action "allow" -AppliedTo $SMTPSecurityGroupProvider,$SMTPSecurityGroupConsumer | out-null
    # Active Directory
    #Active Directory DFW Section
    New-NsxFirewallSection -name "$ActiveDirectoryFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $ActiveDirectoryFirewallSectionName | New-NsxFirewallRule -name "AD Provider to Consumer" -source $AdSecurityGroupProvider -destination $AdSecurityGroupConsumer -service $ActiveDirectoryServiceGroup -action "allow" -AppliedTo $AdSecurityGroupProvider,$AdSecurityGroupConsumer | out-null
    #Consumer to Provider rule
    Get-NsxFirewallSection $ActiveDirectoryFirewallSectionName | New-NsxFirewallRule -name "AD Consumer to Provider" -source $AdSecurityGroupConsumer -destination $AdSecurityGroupProvider -service $ActiveDirectoryServiceGroup -action "allow" -AppliedTo $AdSecurityGroupProvider,$AdSecurityGroupConsumer | out-null

    #Internal Management - RDP
    New-NsxFirewallSection -name "$RDPFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $RDPFirewallSectionName | New-NsxFirewallRule -name "Management RDP Provider to Consumer" -source $InternalRDPSecurityGroupProvider -destination $InternalRDPSecurityGroupConsumer -service $tcp3389 -action "allow" -AppliedTo $InternalRDPSecurityGroupConsumer,$InternalRDPSecurityGroupProvider | out-null
    #Consumer to Provider rule
    Get-NsxFirewallSection $RDPFirewallSectionName | New-NsxFirewallRule -name "Management RDP Consumer to Provider" -source $InternalRDPSecurityGroupConsumer -destination $InternalRDPSecurityGroupProvider -service $tcp3389 -action "allow" -AppliedTo $InternalRDPSecurityGroupConsumer,$InternalRDPSecurityGroupProvider | out-null

    #Internal Management - SSH
    New-NsxFirewallSection -name "$SSHFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $SSHFirewallSectionName | New-NsxFirewallRule -name "Management SSH Provider to Consumer" -source $InternalSSHSecurityGroupProvider -destination $InternalSSHSecurityGroupConsumer -service $tcp22 -action "allow" -AppliedTo $InternalSSHSecurityGroupConsumer,$InternalSSHSecurityGroupProvider | out-null
    #Consumer to Provider rule
    Get-NsxFirewallSection $SSHFirewallSectionName | New-NsxFirewallRule -name "Management SSH Consumer to Provider" -source $InternalSSHSecurityGroupConsumer -destination $InternalSSHSecurityGroupProvider -service $tcp22 -action "allow" -AppliedTo $InternalSSHSecurityGroupConsumer,$InternalSSHSecurityGroupProvider | out-null
    #Internal Management - WEB
    New-NsxFirewallSection -name "$WEBFirewallSectionName" | out-null
    #Provider to Consumer rule
    Get-NsxFirewallSection $WEBFirewallSectionName | New-NsxFirewallRule -name "Management WEB Provider to Consumer" -source $InternalWEBSecurityGroupProvider -destination $InternalWEBSecurityGroupConsumer -service $ManagementServiceGroup -action "allow" -AppliedTo $InternalWEBSecurityGroupConsumer,$InternalWEBSecurityGroupProvider | out-null
    #Consumer to Provider rule
    Get-NsxFirewallSection $WEBFirewallSectionName | New-NsxFirewallRule -name "Management WEB Consumer to Provider" -source $InternalWEBSecurityGroupConsumer -destination $InternalWEBSecurityGroupProvider -service $ManagementServiceGroup -action "allow" -AppliedTo $InternalWEBSecurityGroupConsumer,$InternalWEBSecurityGroupProvider | out-null




# Some validation tests.


#TestFixture "Confirm Objects" {
#      $Securitygroups = @($AdSecurityGroupProviderName,$AdSecurityGroupConsumerName,$ADSecurityGroupApplicationName,$DnsSecurityGroupProviderName,$DnsSecurityGroupConsumerName,$DNSSecurityGroupApplicationName,$SMTPSecurityGroupProviderName,$SMTPSecurityGroupConsumerName,$SMTPSecurityGroupApplicationName,$NTPSecurityGroupProviderNam,$NTPSecurityGroupConsumerName,$NTPSecurityGroupApplicationName,$SyslogSecurityGroupProviderName,$SyslogSecurityGroupConsumerName,$LogInsightSecurityGroupApplicationName ,$DHCPSecurityGroupProviderName,$DHCPSecurityGroupConsumerName,$DHCPSecurityGroupApplicationName,$vCenterSecuritygroupProviderName,$vCenterSecurityGroupConsumerName,$vCenterSecurityGroupApplicationName,$NSXSecurityGroupProviderName,$NSXSecurityGroupConsumerName,$NSXSecurityGroupApplicationName,$vSphereSecurityGroupApplicationName,$WindowsCorporateSecurityGroupName,$LinuxCorporateSecurityGroupName,$ManagementInternalSecurityGroupProviderName,$ManagementInternalSecurityGroupConsumerName,$SDDCSDDCManagementInternalSecurityGroupApplicationName)
#
#      foreach ($group in $SecurityGroups){
#        TestCase "$group reported back from query" {
#          $results = Get-NsxSecurityGroup $group
#          $results.name | Should be $group
#        }
#      }
#
#}
#
#

write-host -foregroundcolor green "

SDDC lockdown complete

The TO-DO list:
* Append Virtual Machines to Security Groups
* Append IP Sets for LB VIPs, hardware endpoints, or objects outside NSX domain
* Monitor traffic with DFW tags and LogInsight
* Apply deny all"
