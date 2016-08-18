## The SDDC lockdown tool

The SDDC lockdown tool. This tool is designed to segment the VMware SDDC framework out of the box. The tool will build a provider/consumer firewall framework for given applications in the SDDC stack. Each release will add more programs to this stack. The initial release is targeting:

* vSphere
* vCenter Service Appliance
* NSX for vSphere
* Log Insight 3.0 cluster
* 
This tool will build the required Security Groups, Services, Service Groups, Security Tags, IPsets, Firewall sections, and Firewall rules. It is then up to the administrator to tag/mark/add workloads or IP addresses to IP sets to begin enforcing the lockdown.

### Provider and Consumer
This SDDC Lockdown tool starts to build out on true provider and consumer security models. The Provider assumes the mantle of delivering said service. A service consumer will do just that - consume. The Firewall rules are applied here between provider and consumers.

Application groups are appended as children to consumer groups. This allows their contents access to a service.

This method allows the correct services to be exposed to consumers of a service. This ensures that when a new application is spun up or torn down that all rules relevant to it are removed and destroyed. The impact then is only the application. This does away with detangled stale firewall rules.

###Authors and Contributors
I am the author of this module. Check our the Issues page to see what is planned and what is coming soon.

###Support or Contact
Please reach out to me here, on twitter as @pandom_ or aburkevmwarecom .
