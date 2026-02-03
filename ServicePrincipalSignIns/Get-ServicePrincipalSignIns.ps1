#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Lists all service principal sign-ins from Microsoft Entra ID and shows last sign-in activities.

.DESCRIPTION
    This script connects to Microsoft Graph API and retrieves service principal sign-in logs,
    displaying the last sign-in activity for each service principal.

.PARAMETER Days
    Number of days to look back for sign-in activities. Default is 30 days.

.PARAMETER ExportPath
    Optional path to export results to CSV.

.EXAMPLE
    .\Get-ServicePrincipalSignIns.ps1
    Lists service principal sign-ins from the last 30 days.

.EXAMPLE
    .\Get-ServicePrincipalSignIns.ps1 -Days 7 -ExportPath "C:\Reports\SPSignIns.csv"
    Lists sign-ins from last 7 days and exports to CSV.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Days = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath = $null
)

# Show export path if specified
if ($ExportPath) {
    Write-Host "Export path: $ExportPath" -ForegroundColor Cyan
}

# Required Graph API permissions
$requiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "Application.Read.All"
)

# Function to get service principal details
function Get-ServicePrincipalDetails {
    param(
        [string]$AppId
    )
    
    try {
        $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'" -OutputType PSObject
        if ($sp.value -and $sp.value.Count -gt 0) {
            return $sp.value[0]
        }
    }
    catch {
        # Service principal might not exist
    }
    
    return $null
}

# Function to get service principal permissions
function Get-ServicePrincipalPermissions {
    param(
        [string]$AppId
    )
    
    $permissions = @{
        Application = @()
        Delegated = @()
    }
    
    try {
        # First get the service principal ID from the AppId
        $spLookup = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'" -OutputType PSObject
        if (-not $spLookup.value -or $spLookup.value.Count -eq 0) {
            return $permissions
        }
        $spId = $spLookup.value[0].id
        
        # Get App Role Assignments (Application permissions)
        $appRoleAssignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments" -OutputType PSObject
        
        foreach ($assignment in $appRoleAssignments.value) {
            try {
                $resourceSp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($assignment.resourceId)" -OutputType PSObject
                $roleName = ($resourceSp.appRoles | Where-Object { $_.id -eq $assignment.appRoleId }).value
                if (-not $roleName) { $roleName = $assignment.appRoleId }
                
                $permissions.Application += "$($assignment.resourceDisplayName): $roleName"
            }
            catch {
                $permissions.Application += "$($assignment.resourceDisplayName): $($assignment.appRoleId)"
            }
        }
        
        # Get OAuth2 Permission Grants (Delegated permissions)
        $oauth2Grants = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/oauth2PermissionGrants" -OutputType PSObject
        
        foreach ($grant in $oauth2Grants.value) {
            $scopes = $grant.scope -split ' ' | Where-Object { $_ }
            foreach ($scope in $scopes) {
                # Get resource display name
                try {
                    $resourceSp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.resourceId)" -OutputType PSObject
                    $permissions.Delegated += "$($resourceSp.displayName): $scope"
                }
                catch {
                    $permissions.Delegated += "$($grant.resourceId): $scope"
                }
            }
        }
    }
    catch {
        # Silently continue if we can't get permissions
    }
    
    return $permissions
}

Write-Host "=== Service Principal Sign-In Report ===" -ForegroundColor Cyan
Write-Host "Checking Microsoft Graph connection..." -ForegroundColor Yellow

# Check if already connected to Microsoft Graph
$context = Get-MgContext -ErrorAction SilentlyContinue

if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        $context = Get-MgContext
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
Write-Host "Tenant ID: $($context.TenantId)" -ForegroundColor Green

# Calculate the date filter - use UTC and proper ISO 8601 format
$startDate = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "`nRetrieving service principal sign-ins from the last $Days days (since $startDate)..." -ForegroundColor Yellow

try {
    # Get service principal sign-in logs using direct API call for better filter support
    Write-Host "Querying sign-in logs..." -ForegroundColor Yellow
    
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge $startDate&`$top=999"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    
    $signInLogs = @()
    if ($response.value) {
        $signInLogs = $response.value
        
        # Handle pagination
        while ($response.'@odata.nextLink') {
            Write-Host "  Fetching more results..." -ForegroundColor Yellow
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -OutputType PSObject
            if ($response.value) {
                $signInLogs += $response.value
            }
        }
    }
    
    Write-Host "  Retrieved $($signInLogs.Count) sign-in events" -ForegroundColor Green
}
catch {
    Write-Host "Error with v1.0 endpoint: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Trying beta endpoint for service principal sign-ins..." -ForegroundColor Yellow
    
    try {
        # Use beta endpoint which has dedicated service principal sign-in logs
        $uri = "https://graph.microsoft.com/beta/auditLogs/servicePrincipalSignInActivities"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        
        if ($response.value) {
            $results = $response.value | Select-Object @{N='ServicePrincipalId';E={$_.appId}},
                @{N='ServicePrincipalName';E={$_.servicePrincipalName}},
                @{N='LastSignInDateTime';E={$_.lastSignInActivity.lastSignInDateTime}},
                @{N='LastDelegatedSignIn';E={$_.lastSignInActivity.lastDelegatedClientSignInDateTime}},
                @{N='LastDelegatedResourceSignIn';E={$_.lastSignInActivity.lastDelegatedResourceSignInDateTime}}
            
            Write-Host "`nFound $($results.Count) service principals with sign-in activity:" -ForegroundColor Green
            
            $results | Sort-Object LastSignInDateTime -Descending | Format-Table -AutoSize
            
            if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
            }
            
            exit 0
        }
    }
    catch {
        Write-Host "Falling back to standard sign-in logs with service principal filter..." -ForegroundColor Yellow
    }
}

# Process standard sign-in logs
if ($signInLogs -and $signInLogs.Count -gt 0) {
    Write-Host "Found $($signInLogs.Count) sign-in events. Processing..." -ForegroundColor Green
    
    # Group by service principal and get last sign-in
    $groupedSignIns = $signInLogs | Group-Object -Property AppId
    
    $results = foreach ($group in $groupedSignIns) {
        $lastSignIn = $group.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
        
        # Get service principal details
        $spDetails = Get-ServicePrincipalDetails -AppId $lastSignIn.AppId
        $spDisplayName = if ($spDetails) { $spDetails.displayName } else { $lastSignIn.AppDisplayName }
        
        # Get permissions
        $permissions = Get-ServicePrincipalPermissions -AppId $lastSignIn.AppId
        $appPermissions = $permissions.Application -join " | "
        $delegatedPermissions = $permissions.Delegated -join " | "
        
        [PSCustomObject]@{
            ServicePrincipalName  = $spDisplayName
            AppId                 = $lastSignIn.AppId
            LastSignInDateTime   = $lastSignIn.CreatedDateTime
            IPAddress            = $lastSignIn.IPAddress
            Location             = "$($lastSignIn.Location.City), $($lastSignIn.Location.CountryOrRegion)"
            Status               = if ($lastSignIn.Status.ErrorCode -eq 0) { "Success" } else { "Failed: $($lastSignIn.Status.FailureReason)" }
            ResourceDisplayName  = $lastSignIn.ResourceDisplayName
            SignInCount          = $group.Count
            ApplicationPermissions = $appPermissions
            DelegatedPermissions   = $delegatedPermissions
        }
    }
    
    # Display results
    Write-Host "`n=== Last Sign-In Activity per Service Principal ===" -ForegroundColor Cyan
    $results | Sort-Object LastSignInDateTime -Descending | Format-Table ServicePrincipalName, AppId, LastSignInDateTime, Status, SignInCount -AutoSize
    
    # Display permissions details
    Write-Host "`n=== Permissions Details ===" -ForegroundColor Cyan
    foreach ($result in ($results | Sort-Object LastSignInDateTime -Descending)) {
        Write-Host "`n$($result.ServicePrincipalName) ($($result.AppId)):" -ForegroundColor White
        if ($result.ApplicationPermissions) {
            Write-Host "  Application Permissions:" -ForegroundColor Yellow
            $result.ApplicationPermissions -split " \| " | ForEach-Object {
                Write-Host "    - $_" -ForegroundColor Gray
            }
        }
        if ($result.DelegatedPermissions) {
            Write-Host "  Delegated Permissions:" -ForegroundColor Yellow
            $result.DelegatedPermissions -split " \| " | ForEach-Object {
                Write-Host "    - $_" -ForegroundColor Gray
            }
        }
        if (-not $result.ApplicationPermissions -and -not $result.DelegatedPermissions) {
            Write-Host "  No permissions found" -ForegroundColor DarkGray
        }
    }
    
    # Export if path specified
    if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
        
        # Verify file was created
        if (Test-Path $ExportPath) {
            $fileInfo = Get-Item $ExportPath
            Write-Host "  File size: $($fileInfo.Length) bytes" -ForegroundColor Gray
        }
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total unique service principals: $($results.Count)"
    Write-Host "Total sign-in events: $($signInLogs.Count)"
    Write-Host "Date range: Last $Days days"
}
else {
    Write-Host "`nNo service principal sign-ins found in the last $Days days." -ForegroundColor Yellow
    Write-Host "This could mean:"
    Write-Host "  - No service principals have signed in during this period"
    Write-Host "  - Sign-in logs retention period may be shorter"
    Write-Host "  - You may need additional permissions (AuditLog.Read.All)"
}

# Also get service principals with their last sign-in activity from the applications endpoint
Write-Host "`n=== Fetching Service Principal Last Sign-In Activity ===" -ForegroundColor Cyan

try {
    # Get all service principals with sign-in activity (beta API)
    $uri = "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities"
    $spActivities = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    
    if ($spActivities.value) {
        $spResults = foreach ($sp in $spActivities.value) {
            # Get service principal details
            $spDetails = Get-ServicePrincipalDetails -AppId $sp.appId
            $spDisplayName = if ($spDetails) { $spDetails.displayName } else { "N/A" }
            
            # Get permissions
            $permissions = Get-ServicePrincipalPermissions -AppId $sp.appId
            $appPermissions = $permissions.Application -join " | "
            $delegatedPermissions = $permissions.Delegated -join " | "
            
            [PSCustomObject]@{
                AppId                          = $sp.appId
                ServicePrincipalName           = $spDisplayName
                ServicePrincipalId             = $sp.id
                LastSignInDateTime             = $sp.lastSignInActivity.lastSignInDateTime
                LastSignInRequestId            = $sp.lastSignInActivity.lastSignInRequestId
                DelegatedClientSignIn          = $sp.delegatedClientSignInActivity.lastSignInDateTime
                DelegatedResourceSignIn        = $sp.delegatedResourceSignInActivity.lastSignInDateTime
                ApplicationCredentialSignIn    = $sp.applicationAuthenticationClientSignInActivity.lastSignInDateTime
                ManagedIdentitySignIn          = $sp.applicationAuthenticationManagedIdentitySignInActivity.lastSignInDateTime
                ApplicationPermissions         = $appPermissions
                DelegatedPermissions           = $delegatedPermissions
            }
        }
        
        Write-Host "`nService Principal Sign-In Activities:" -ForegroundColor Green
        $spResults | Sort-Object LastSignInDateTime -Descending | Format-Table ServicePrincipalName, AppId, LastSignInDateTime -AutoSize
        
        # Display permissions details for beta endpoint
        Write-Host "`n=== Permissions Details ===" -ForegroundColor Cyan
        foreach ($result in ($spResults | Sort-Object LastSignInDateTime -Descending)) {
            Write-Host "`n$($result.ServicePrincipalName) ($($result.AppId)):" -ForegroundColor White
            if ($result.ApplicationPermissions) {
                Write-Host "  Application Permissions:" -ForegroundColor Yellow
                $result.ApplicationPermissions -split " \| " | ForEach-Object {
                    Write-Host "    - $_" -ForegroundColor Gray
                }
            }
            if ($result.DelegatedPermissions) {
                Write-Host "  Delegated Permissions:" -ForegroundColor Yellow
                $result.DelegatedPermissions -split " \| " | ForEach-Object {
                    Write-Host "    - $_" -ForegroundColor Gray
                }
            }
            if (-not $result.ApplicationPermissions -and -not $result.DelegatedPermissions) {
                Write-Host "  No permissions found" -ForegroundColor DarkGray
            }
        }
        
        if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
            $detailedPath = $ExportPath -replace '\.csv$', '_detailed.csv'
            $spResults | Export-Csv -Path $detailedPath -NoTypeInformation -Force
            Write-Host "Detailed results exported to: $detailedPath" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "Note: Detailed service principal activity endpoint not available or requires additional permissions." -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

Write-Host "`nScript completed." -ForegroundColor Cyan
