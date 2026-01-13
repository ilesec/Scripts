## MDEDeviceGroupsToSecurityGroups, sync MDE Device Groups to Azure AD Security Groups
## Author: Ilkka Hyvönen
## Version: 0.1
# Requires: Microsoft.Graph PowerShell modules
# Required Microsoft Graph API permissions: Machine.Read.All, Group.ReadWrite.All, Device.Read.All

$tenantId = ' ' ### Paste your own tenant ID here
$appId = ' ' ### Paste your own app ID here
$appSecret = ' ' ### Paste your own app secret here

# Authenticate and get token with the service principal for MDE API
$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

Write-Host "Authenticating to MDE API..."
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$mdeToken = $authResponse.access_token

# Store MDE auth token into header
$mdeHeaders = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $mdeToken"
}

# Authenticate to Microsoft Graph
Write-Host "Authenticating to Microsoft Graph..."
$graphResourceUri = 'https://graph.microsoft.com'
$graphOAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
$graphAuthBody = [Ordered] @{
    resource = "$graphResourceUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

$graphAuthResponse = Invoke-RestMethod -Method Post -Uri $graphOAuthUri -Body $graphAuthBody -ErrorAction Stop
$graphToken = $graphAuthResponse.access_token

# Store Graph auth token into header
$graphHeaders = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $graphToken"
}

# Get all MDE devices with their RBAC group names
Write-Host "`nFetching MDE devices and their device groups..."
$mdeDevices = Invoke-RestMethod -Method GET -Headers $mdeHeaders -Uri "https://api.securitycenter.microsoft.com/api/machines" | Select-Object -ExpandProperty value

Write-Host "Found $($mdeDevices.Count) MDE devices"

# Collect all unique device groups (rbacGroupName) and group devices by device group
$groupToDevicesMap = @{}
foreach ($device in $mdeDevices) {
    if ($device.rbacGroupName) {
        $rbacGroupName = $device.rbacGroupName
        if (-not $groupToDevicesMap.ContainsKey($rbacGroupName)) {
            $groupToDevicesMap[$rbacGroupName] = @()
        }
        $groupToDevicesMap[$rbacGroupName] += $device
    }
}

Write-Host "Found $($groupToDevicesMap.Keys.Count) unique device groups:`n"
$groupToDevicesMap.Keys | ForEach-Object {
    Write-Host "  - $_ ($($groupToDevicesMap[$_].Count) devices)"
}

# Get all Azure AD Security Groups
Write-Host "`nFetching Azure AD Security Groups..."
$aadGroups = Invoke-RestMethod -Method GET -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=securityEnabled eq true" | Select-Object -ExpandProperty value

# Process each device group
Write-Host "`nProcessing MDE Device Groups...`n"
foreach ($groupName in $groupToDevicesMap.Keys) {
    $devicesInGroup = $groupToDevicesMap[$groupName]
    
    Write-Host "Processing MDE Device Group: '$groupName'"
    Write-Host "  Processing $($devicesInGroup.Count) devices in this group..."
    
    # Check if a corresponding Security Group exists
    # Naming convention: MDE-Group-<GroupName>
    $securityGroupName = "MDE-Group-$groupName"
    $existingGroup = $aadGroups | Where-Object { $_.displayName -eq $securityGroupName }
    
    if ($existingGroup) {
        Write-Host "  Security Group '$securityGroupName' already exists (ID: $($existingGroup.id))"
        $securityGroupId = $existingGroup.id
    } else {
        Write-Host "  Security Group '$securityGroupName' does not exist. Creating..."
        
        # Create new Security Group
        $newGroupBody = @{
            displayName = $securityGroupName
            mailNickname = $securityGroupName -replace '[^a-zA-Z0-9]', ''
            mailEnabled = $false
            securityEnabled = $true
            description = "Synced from MDE Device Group: $groupName"
        }
        
        try {
            $newGroup = Invoke-RestMethod -Method POST -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/groups" -Body ($newGroupBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
            $securityGroupId = $newGroup.id
            Write-Host "  Successfully created Security Group '$securityGroupName' (ID: $securityGroupId)" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to create Security Group '$securityGroupName': $_" -ForegroundColor Red
            continue
        }
    }
    
    # Get current members of the Security Group
    Write-Host "  Fetching current members of Security Group..."
    try {
        $securityGroupMembers = Invoke-RestMethod -Method GET -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/groups/$securityGroupId/members" | Select-Object -ExpandProperty value
        Write-Host "    Found $($securityGroupMembers.Count) current members"
    } catch {
        Write-Host "    Failed to fetch Security Group members: $_" -ForegroundColor Red
        $securityGroupMembers = @()
    }
    
    # Sync devices to Security Group
    Write-Host "  Syncing devices to Security Group..."
    $devicesAdded = 0
    $devicesSkipped = 0
    $devicesFailed = 0
    $devicesRemoved = 0
    
    # Build list of Azure AD Device IDs that should be in the group
    $expectedDeviceIds = @()
    
    foreach ($mdeDevice in $devicesInGroup) {
        $deviceName = $mdeDevice.computerDnsName
        $azureAdDeviceId = $mdeDevice.aadDeviceId
        
        if (-not $azureAdDeviceId) {
            Write-Host "    Device '$deviceName' has no Azure AD Device ID. Skipping..." -ForegroundColor Yellow
            $devicesSkipped++
            continue
        }
        
        $expectedDeviceIds += $azureAdDeviceId
        
        # Check if device is already a member
        $isMember = $securityGroupMembers | Where-Object { $_.id -eq $azureAdDeviceId }
        
        if ($isMember) {
            Write-Host "    Device '$deviceName' is already a member. Skipping..."
            $devicesSkipped++
            continue
        }
        
        # Add device to Security Group
        $addMemberBody = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$azureAdDeviceId"
        }
        
        try {
            Invoke-RestMethod -Method POST -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/groups/$securityGroupId/members/`$ref" -Body ($addMemberBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
            Write-Host "    Added device '$deviceName' to Security Group" -ForegroundColor Green
            $devicesAdded++
        } catch {
            Write-Host "    Failed to add device '$deviceName' to Security Group: $_" -ForegroundColor Red
            $devicesFailed++
        }
    }
    
    # Remove devices that are no longer in the MDE device group
    Write-Host "  Checking for devices to remove from Security Group..."
    foreach ($member in $securityGroupMembers) {
        if ($member.'@odata.type' -eq '#microsoft.graph.device') {
            if ($expectedDeviceIds -notcontains $member.id) {
                $memberDisplayName = $member.displayName
                Write-Host "    Device '$memberDisplayName' is no longer in MDE group. Removing..."
                
                try {
                    Invoke-RestMethod -Method DELETE -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/groups/$securityGroupId/members/$($member.id)/`$ref" -ErrorAction Stop
                    Write-Host "    Removed device '$memberDisplayName' from Security Group" -ForegroundColor Green
                    $devicesRemoved++
                } catch {
                    Write-Host "    Failed to remove device '$memberDisplayName' from Security Group: $_" -ForegroundColor Red
                }
            }
        }
    }
    
    Write-Host "  Summary: Added: $devicesAdded | Skipped: $devicesSkipped | Failed: $devicesFailed | Removed: $devicesRemoved"
    Write-Host ""
}

Write-Host "`nSync completed!" -ForegroundColor Green
