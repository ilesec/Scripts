# This script enables EncryptionAtHost on all eligible VMs in the specified subscription.
# Prerequisites: A Key Vault with a Key and a Disk Encryption Set (DES) configured to use that Key.
# Familirize yourself with the restrictions and requirements: https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-host-based-encryption-portal?tabs=azure-powershell 
Connect-AzAccount
Set-AzContext -SubscriptionId "<your subscriptionId here>"

# ============================================
# CONFIGURATION - Customer Managed Keys (CMK)
# ============================================
# Specify the Disk Encryption Set resource ID for CMK
$diskEncryptionSetId = "/subscriptions/<your subscriptionId here>/resourceGroups/<your resource group name>/providers/Microsoft.Compute/diskEncryptionSets/<your disk encryption set name>"

# Set to $true to apply CMK to disks, $false to only enable EncryptionAtHost
$enableCMK = $true

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

    # 4. Check OS disk for Disk Encryption Set (skip if already has CMK and we're not re-applying)
    $osDiskId = $vm.StorageProfile.OSDisk.ManagedDisk.Id
    # Parse resource ID to extract disk name and resource group
    $osDiskName = $osDiskId.Split('/')[-1]
    $osDiskRg   = ($osDiskId -split '/resourceGroups/')[1].Split('/')[0]
    $osDisk     = Get-AzDisk -ResourceGroupName $osDiskRg -DiskName $osDiskName

    $existingDES = $osDisk.Encryption.DiskEncryptionSetId
    if ($existingDES -and (-not $enableCMK)) {
        Write-Host "  -> Skipped: Disk Encryption Set already configured"
        continue
    }

    # --- All conditions met ---
    $appliedCMK = $false

    # Apply CMK to OS disk if enabled
    if ($enableCMK -and $diskEncryptionSetId -notlike "*<*") {
        Write-Host "  -> Applying CMK to OS disk: $osDiskName"
        
        $osDiskConfig = New-AzDiskUpdateConfig -EncryptionType "EncryptionAtRestWithCustomerKey" -DiskEncryptionSetId $diskEncryptionSetId
        Update-AzDisk -ResourceGroupName $osDiskRg -DiskName $osDiskName -DiskUpdate $osDiskConfig | Out-Null
        $appliedCMK = $true

        # Apply CMK to all data disks
        foreach ($dataDisk in $vm.StorageProfile.DataDisks) {
            $dataDiskId   = $dataDisk.ManagedDisk.Id
            $dataDiskName = $dataDiskId.Split('/')[-1]
            $dataDiskRg   = ($dataDiskId -split '/resourceGroups/')[1].Split('/')[0]
            
            Write-Host "  -> Applying CMK to data disk: $dataDiskName"
            $dataDiskConfig = New-AzDiskUpdateConfig -EncryptionType "EncryptionAtRestWithCustomerKey" -DiskEncryptionSetId $diskEncryptionSetId
            Update-AzDisk -ResourceGroupName $dataDiskRg -DiskName $dataDiskName -DiskUpdate $dataDiskConfig | Out-Null
        }
    }

    # Enable EncryptionAtHost
    Write-Host "  -> Enabling EncryptionAtHost"

    $vm.SecurityProfile = @{
        EncryptionAtHost = $true
    }

    Update-AzVM -ResourceGroupName $rg -VM $vm | Out-Null

    $results += [PSCustomObject]@{
        VMName           = $vmName
        ResourceGroup    = $rg
        PowerState       = $state
        EncryptionAtHost = "Enabled"
        CMK              = if ($appliedCMK) { "Applied" } else { "No" }
        DataDisks        = $vm.StorageProfile.DataDisks.Count
        ADE              = "No"
        ActionTaken      = "Updated"
    }
}

# Output summary
$results | Format-Table -AutoSize

