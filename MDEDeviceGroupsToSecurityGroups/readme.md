# MDE Device Groups to Security Groups

## Overview
This PowerShell script synchronizes Microsoft Defender for Endpoint (MDE) device groups to Azure AD (Entra) Security Groups. For each MDE device group, the script creates a corresponding security group (if it doesn't exist) and ensures its membership matches the devices in the MDE group.

## Features
- Automatically creates Azure AD Security Groups for each MDE device group
- Syncs device membership from MDE to Azure AD Security Groups
- Removes devices from Security Groups if they're no longer in the MDE device group
- Uses naming convention: `MDE-Group-<DeviceGroupName>`
- Provides detailed logging and progress information

## Prerequisites
- Azure AD App Registration with the following Microsoft Graph API permissions:
  - `Machine.Read.All` - Read MDE device and device group information
  - `Group.ReadWrite.All` - Create and manage Security Groups
  - `Device.Read.All` - Read Azure AD device information
- Client ID, Client Secret, and Tenant ID from your App Registration

## Configuration
Edit the script and fill in the following variables at the top:
```powershell
$tenantId = ' '    # Your Azure AD Tenant ID
$appId = ' '       # Your App Registration Client ID
$appSecret = ' '   # Your App Registration Client Secret
```

## Usage
Run the script manually or schedule it as a task:
```powershell
.\MDEDeviceGroupsToSecurityGroups.ps1
```

## How It Works
1. Authenticates to MDE API and Microsoft Graph API
2. Retrieves all MDE device groups
3. For each device group:
   - Fetches all devices in that group
   - Creates or finds the corresponding Azure AD Security Group (naming: `MDE-Group-<GroupName>`)
   - Adds missing devices to the Security Group
   - Removes devices that are no longer in the MDE device group
4. Provides summary statistics for each group

## Notes
- Only devices with an Azure AD Device ID can be added to Security Groups
- The script uses REST API calls rather than PowerShell modules for better control
- Security Groups are created with `securityEnabled = true` and `mailEnabled = false`
- The script includes automatic cleanup to remove devices from Security Groups when they're removed from MDE device groups

## Troubleshooting
- If authentication fails, verify your App Registration credentials and API permissions
- Ensure the service principal has been granted admin consent for the required permissions
- Check that devices are Azure AD joined or hybrid joined (they need an aadDeviceId)

## Author
Ilkka Hyvönen

## Version
0.1
