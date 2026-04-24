Connect-AzAccount
Set-AzContext -SubscriptionId "Your subscriptionId here"

#Register the feature in the subscription. This is a one-time operation per subscription.
Register-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "EncryptionAtHost"

# Wait until this returns "Registered"
Get-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "EncryptionAtHost"

$results = @()

# Get all VMs incl. power state
foreach ($vm in (Get-AzVM -Status)) {
    $vmName = $vm.Name
    $rg     = $vm.ResourceGroupName
    $state  = $vm.PowerState  # Direct property from Get-AzVM -Status

    Write-Host "Checking VM: $vmName ($state)"

    # 1. Must be deallocated
    if ($state -ne "VM deallocated") {
        Write-Host "  -> Skipped: VM not deallocated (power state: $state)"
        continue
    }

    # 2. EncryptionAtHost must not already be enabled
    if ($vm.SecurityProfile -and $vm.SecurityProfile.EncryptionAtHost -eq $true) {
        Write-Host "  -> Skipped: EncryptionAtHost already enabled"
        continue
    }

    # 3. Skip Azure Disk Encryption (ADE)
    $ade = $vm.Extensions |
        Where-Object {
            $_.Publisher -eq "Microsoft.Azure.Security" -and
            $_.ExtensionType -like "AzureDiskEncryption*"
        }

    if ($ade) {
        Write-Host "  -> Skipped: Azure Disk Encryption detected"
        continue
    }

    # 4. Check OS disk for Disk Encryption Set
    $osDiskId = $vm.StorageProfile.OSDisk.ManagedDisk.Id
    # Parse resource ID to extract disk name and resource group
    $osDiskName = $osDiskId.Split('/')[-1]
    $osDiskRg   = ($osDiskId -split '/resourceGroups/')[1].Split('/')[0]
    $osDisk     = Get-AzDisk -ResourceGroupName $osDiskRg -DiskName $osDiskName

    if ($osDisk.Encryption -and $osDisk.Encryption.DiskEncryptionSetId) {
        Write-Host "  -> Skipped: Disk Encryption Set detected"
        continue
    }

    # --- All conditions met ---
    Write-Host "  -> Enabling EncryptionAtHost"

    $vm.SecurityProfile = @{
        EncryptionAtHost = $true
    }

    Update-AzVM -ResourceGroupName $rg -VM $vm | Out-Null

    $results += [PSCustomObject]@{
        VMName           = $vmName
        ResourceGroup    = $rg
        PowerState       = $state
        EncryptionAtHost = "Enabled (model)"
        DES              = "No"
        ADE              = "No"
        ActionTaken      = "Updated"
    }
}

# Output summary
$results | Format-Table -AutoSize

