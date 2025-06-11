## AzureTagsToMDE, add Azure VM tags to Microsoft Defender for Endpoint devices
## Author: Ilkka Hyvönen
## Version: 0.1
# Requires: Az.Resources, Microsoft.Graph, and Defender ATP PowerShell modules
$tenantId = ' ' ### Paste your own tenant ID here
$appId = ' ' ### Paste your own app ID here
$appSecret = ' ' ### Paste your own app keys here

# Login to Azure with a service principal. It needs to have reader permissions on the subscription.
$credential = New-Object -TypeName System.Management.Automation.PSCredential ($appId, (ConvertTo-SecureString $appSecret -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -TenantId $tenantId -Credential $credential

# Get all Azure VMs and their tags
$azureVMs = Get-AzVM | Select-Object Name, ResourceGroupName, @{Name="Tags";Expression={$_.Tags}}

$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
# Store auth token into header for future use
$headers = @{
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token"
    }

# Login to Microsoft Graph for Defender for Endpoint
# $AccessToken = $token | ConvertTo-SecureString -AsPlainText -Force
# Connect-MgGraph -AccessToken $AccessToken

# Get all Defender for Endpoint devices and their tags
$defenderDevices = Invoke-RestMethod -Method GET -Headers $headers -Uri "https://api.security.microsoft.com/api/machines" | Select-Object -ExpandProperty value

# Output Defender for Endpoint device tags
Write-Host "`nDefender for Endpoint Device Tags:"
$defenderDevices | ForEach-Object {
    Write-Host "Device: $($_.computerDnsName) | Tags: $($_.machineTags)"
}

# Output Azure VM tags
Write-Host "Azure VM Tags:"
$azureVMs | ForEach-Object {
    Write-Host "VM: $($_.Name) | Tags: $($_.Tags)"
}

# Sync Azure VM tags to Defender for Endpoint
foreach ($vm in @($azureVMs)) {
    $vmName = $vm.Name
    $vmTags = $vm.Tags

    # Try to match by FQDN or short name
    $defenderDevice = $defenderDevices | Where-Object {
        ($_.computerDnsName -ieq $vmName) -or
        ($_.computerDnsName -and ($_.computerDnsName.Split('.')[0] -ieq $vmName))
    }

    if (-not $defenderDevice) {
        Write-Host "No matching Defender device found for VM '$vmName'. Skipping..."
        continue
    }

    # If multiple matches, take the first
    if ($defenderDevice -is [System.Array]) {
        $defenderDevice = $defenderDevice[0]
    }

    $deviceId = $defenderDevice.id
    Write-Host "Syncing tags for VM '$vmName' to Defender device '$($defenderDevice.computerDnsName)' (ID: $deviceId)"

    if ($vmTags) {
        foreach ($tagKey in $vmTags.Keys) {
            $tagValue = $vmTags[$tagKey]
            $tagString = "$tagKey=$tagValue"

            # Check if tag already exists in Defender
            if ($defenderDevice.machineTags -notcontains $tagString) {
                $body = @{
                    "Value"  = $tagString
                    "Action" = "Add"
                }
                Write-Host "Adding tag '$tagString' to Defender device '$vmName'..."
                try {
                    Invoke-RestMethod -Method POST -Headers $headers -Uri "https://api.security.microsoft.com/api/machines/$deviceId/tags" -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                } catch {
                    Write-Host "Failed to add tag '$tagString' to device '$vmName' (ID: $deviceId): $_"
                }
            }
        }
    }
}
