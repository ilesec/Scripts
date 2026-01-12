# MDE Device Groups to Security Groups Sync

This PowerShell script synchronizes Microsoft Defender for Endpoint (MDE) Device Groups into Azure AD Security Groups.

## Features

- Automatically discovers all MDE Device Groups
- Creates corresponding Azure AD Security Groups if they don't exist
- Syncs device membership from MDE Device Groups to Security Groups
- Uses naming convention: `MDE-<GroupName>` for created Security Groups
- Skips devices that are already members to avoid duplicates
- Provides detailed progress and summary information

## Prerequisites

- Azure AD App Registration with the following permissions:
  - **Microsoft Defender for Endpoint API**:
    - `Machine.Read.All` (to read device groups and devices)
  - **Microsoft Graph API**:
    - `Group.ReadWrite.All` (to create and manage security groups)
    - `Device.Read.All` (to read Azure AD device information)
    - `GroupMember.ReadWrite.All` (to manage group membership)

## Setup

1. Create an App Registration in Azure AD
2. Grant the required API permissions (see Prerequisites)
3. Create a client secret for the app
4. Update the script with your credentials:
   ```powershell
   $tenantId = 'your-tenant-id-here'
   $appId = 'your-app-id-here'
   $appSecret = 'your-app-secret-here'
   ```

## Usage

Run the script:
```powershell
.\MDEDeviceGroupsToSecurityGroups.ps1
```

## How It Works

1. Authenticates to both MDE API and Microsoft Graph API
2. Retrieves all MDE Device Groups
3. For each MDE Device Group:
   - Checks if a corresponding Security Group exists (with prefix `MDE-`)
   - Creates the Security Group if it doesn't exist
   - Retrieves all devices in the MDE Device Group
   - Adds devices to the Security Group using their Azure AD Device ID
   - Skips devices without Azure AD Device ID or already in the group

## Notes

- The script uses Azure AD Device IDs to add devices to Security Groups
- Devices without Azure AD Device IDs will be skipped
- Security Groups are created with the naming convention: `MDE-<GroupName>`
- The script is idempotent - you can run it multiple times safely

## Version

Version: 0.1

## Author

Ilkka Hyvönen
