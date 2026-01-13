# MDE Tags to Security Groups Sync

This PowerShell script synchronizes Microsoft Defender for Endpoint (MDE) device tags into Azure AD Security Groups. It creates a separate security group for each unique tag found on MDE devices.

## Features

- Automatically discovers all unique MDE device tags
- Creates corresponding Azure AD Security Groups if they don't exist
- Syncs device membership based on tags to Security Groups
- Uses naming convention: `MDE-Tag-<TagName>` for created Security Groups
- Skips devices that are already members to avoid duplicates
- Provides detailed progress and summary information
- Supports devices with multiple tags (device can be in multiple groups)

## Prerequisites

- Azure AD App Registration with the following permissions:
  - **Microsoft Defender for Endpoint API** (`https://api.securitycenter.windows.com`):
    - `Machine.Read.All` (to read all machine information including tags)
  - **Microsoft Graph API** (`https://graph.microsoft.com`):
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
2. Retrieves all MDE devices and their tags
3. Groups devices by their unique tags
4. For each unique tag:
   - Checks if a corresponding Security Group exists (with prefix `MDE-Tag-`)
   - Creates the Security Group if it doesn't exist
   - Adds all devices with that tag to the Security Group using their Azure AD Device ID
   - Skips devices without Azure AD Device ID or already in the group

## Notes

- The script uses Azure AD Device IDs to add devices to Security Groups
- Devices without Azure AD Device IDs will be skipped
- Devices without any tags will not be processed
- Security Groups are created with the naming convention: `MDE-Tag-<TagName>`
- Devices with multiple tags will be added to multiple Security Groups
- The script is idempotent - you can run it multiple times safely

## Version

Version: 0.2 (Updated to sync by tags instead of device groups)

## Author

Ilkka Hyvönen
