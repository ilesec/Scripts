## MDEDeviceGroupsToSecurityGroups, sync MDE Device Groups to Azure AD Security Groups
## Author: Ilkka Hyvönen
## Version: 0.1
# Requires: Microsoft.Graph PowerShell modules
# Required Microsoft Graph API permissions: DeviceManagementManagedDevices.Read.All, Group.ReadWrite.All, Device.Read.All

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

# Get all MDE Device Groups
Write-Host "`nFetching MDE Device Groups..."
$mdeDeviceGroups = Invoke-RestMethod -Method GET -Headers $mdeHeaders -Uri "https://api.security.microsoft.com/api/machinegroups" | Select-Object -ExpandProperty value

Write-Host "Found $($mdeDeviceGroups.Count) MDE Device Groups:`n"
$mdeDeviceGroups | ForEach-Object {
    Write-Host "  - $($_.name) (ID: $($_.id))"
}

# Get all Azure AD Security Groups
Write-Host "`nFetching Azure AD Security Groups..."
$aadGroups = Invoke-RestMethod -Method GET -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=securityEnabled eq true" | Select-Object -ExpandProperty value

# Process each MDE Device Group
Write-Host "`nProcessing MDE Device Groups...`n"
foreach ($mdeGroup in $mdeDeviceGroups) {
    $mdeGroupName = $mdeGroup.name
    $mdeGroupId = $mdeGroup.id
    
    Write-Host "Processing MDE Device Group: '$mdeGroupName'"
    
    # Check if a corresponding Security Group exists
    # Naming convention: MDE-<GroupName>
    $securityGroupName = "MDE-$mdeGroupName"
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
            description = "Synced from MDE Device Group: $mdeGroupName (ID: $mdeGroupId)"
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
    
    # Get devices in the MDE Device Group
    Write-Host "  Fetching devices in MDE Device Group..."
    try {
        $mdeDevicesInGroup = Invoke-RestMethod -Method GET -Headers $mdeHeaders -Uri "https://api.security.microsoft.com/api/machinegroups/$mdeGroupId/machines" | Select-Object -ExpandProperty value
        Write-Host "    Found $($mdeDevicesInGroup.Count) devices in MDE Device Group"
    } catch {
        Write-Host "    Failed to fetch devices from MDE Device Group: $_" -ForegroundColor Red
        continue
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
    
    foreach ($mdeDevice in $mdeDevicesInGroup) {
        $deviceName = $mdeDevice.computerDnsName
        $mdeDeviceId = $mdeDevice.id
        $azureAdDeviceId = $mdeDevice.aadDeviceId
        
        if (-not $azureAdDeviceId) {
            Write-Host "    Device '$deviceName' has no Azure AD Device ID. Skipping..." -ForegroundColor Yellow
            $devicesSkipped++
            continue
        }
        
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
    
    Write-Host "  Summary: Added: $devicesAdded | Skipped: $devicesSkipped | Failed: $devicesFailed"
    Write-Host ""
}

Write-Host "`nSync completed!" -ForegroundColor Green
