Get-NsxFirewallSection | Remove-NsxFirewallSection -force -confirm:$false
Get-NsxSecurityGroup | Remove-NsxSecurityGroup -confirm:$false
Get-NsxServiceGroup | Remove-NsxServiceGroup -confirm:$false
Get-NsxService | Remove-NsxService -confirm:$false
Get-NsxSecurityTag | Remove-NsxSecurityTag -confirm:$false
