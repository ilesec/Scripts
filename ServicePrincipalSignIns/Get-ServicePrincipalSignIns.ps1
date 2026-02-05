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

.EXAMPLE
    .\Get-ServicePrincipalSignIns.ps1 -IncludePermissions
    Lists sign-ins with detailed permission information (slower).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Days = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath = $null,

    [Parameter()]
    [switch]$IncludePermissions
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

# First, get ALL service principals with their last sign-in activity (this shows historical last sign-in regardless of date)
Write-Host "`n=== Fetching Last Sign-In Activity for All Service Principals ===" -ForegroundColor Cyan

# Build a hashtable of all service principals for fast lookup
Write-Host "  Building service principal cache..." -ForegroundColor Yellow
$spCache = @{}
try {
    $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=appId,id,displayName&`$top=999"
    $spResponse = Invoke-MgGraphRequest -Method GET -Uri $spUri -OutputType PSObject
    if ($spResponse.value) {
        foreach ($sp in $spResponse.value) {
            $spCache[$sp.appId] = $sp
        }
        while ($spResponse.'@odata.nextLink') {
            $spResponse = Invoke-MgGraphRequest -Method GET -Uri $spResponse.'@odata.nextLink' -OutputType PSObject
            if ($spResponse.value) {
                foreach ($sp in $spResponse.value) {
                    $spCache[$sp.appId] = $sp
                }
            }
        }
    }
    Write-Host "  Cached $($spCache.Count) service principals" -ForegroundColor Green
}
catch {
    Write-Host "  Could not build SP cache: $($_.Exception.Message)" -ForegroundColor Yellow
}

$allSpResults = @()
try {
    # Get all service principals with sign-in activity (beta API) - this shows the ACTUAL last sign-in date
    $uri = "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    
    if ($response.value) {
        $allSpActivities = @($response.value)
        
        # Handle pagination
        while ($response.'@odata.nextLink') {
            Write-Host "  Fetching more service principals..." -ForegroundColor Yellow
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -OutputType PSObject
            if ($response.value) {
                $allSpActivities += $response.value
            }
        }
        
        Write-Host "  Found $($allSpActivities.Count) service principals with sign-in activity" -ForegroundColor Green
        
        $totalCount = $allSpActivities.Count
        $currentIndex = 0
        
        $allSpResults = foreach ($sp in $allSpActivities) {
            $currentIndex++
            
            # Get service principal details from cache (fast)
            $spDetails = $spCache[$sp.appId]
            $spDisplayName = if ($spDetails) { $spDetails.displayName } else { "N/A" }
            
            # Get permissions only if requested (slow operation)
            $appPermissions = ""
            $delegatedPermissions = ""
            if ($IncludePermissions) {
                if ($currentIndex % 10 -eq 0) {
                    Write-Host "  Processing permissions: $currentIndex of $totalCount..." -ForegroundColor Yellow
                }
                $permissions = Get-ServicePrincipalPermissions -AppId $sp.appId
                $appPermissions = $permissions.Application -join " | "
                $delegatedPermissions = $permissions.Delegated -join " | "
            }
            
            # Determine the most recent sign-in from all activity types
            $lastSignInDates = @(
                $sp.lastSignInActivity.lastSignInDateTime,
                $sp.delegatedClientSignInActivity.lastSignInDateTime,
                $sp.delegatedResourceSignInActivity.lastSignInDateTime,
                $sp.applicationAuthenticationClientSignInActivity.lastSignInDateTime,
                $sp.applicationAuthenticationManagedIdentitySignInActivity.lastSignInDateTime
            ) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Descending
            
            $mostRecentSignIn = if ($lastSignInDates) { [string]$lastSignInDates[0] } else { $null }
            
            [PSCustomObject]@{
                ServicePrincipalName           = $spDisplayName
                AppId                          = $sp.appId
                LastSignInDateTime             = $mostRecentSignIn
                LastDelegatedClientSignIn      = [string]$sp.delegatedClientSignInActivity.lastSignInDateTime
                LastDelegatedResourceSignIn    = [string]$sp.delegatedResourceSignInActivity.lastSignInDateTime
                LastAppCredentialSignIn        = [string]$sp.applicationAuthenticationClientSignInActivity.lastSignInDateTime
                LastManagedIdentitySignIn      = [string]$sp.applicationAuthenticationManagedIdentitySignInActivity.lastSignInDateTime
                ApplicationPermissions         = $appPermissions
                DelegatedPermissions           = $delegatedPermissions
            }
        }
    }
}
catch {
    Write-Host "Note: Beta reports endpoint not available. Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Display all service principal results
if ($allSpResults -and $allSpResults.Count -gt 0) {
    Write-Host "`nAll Service Principals - Last Sign-In Activity:" -ForegroundColor Green
    $allSpResults | Sort-Object LastSignInDateTime -Descending | Format-Table ServicePrincipalName, AppId, LastSignInDateTime, LastAppCredentialSignIn, LastManagedIdentitySignIn -AutoSize
    
    # Display permissions details only if requested
    if ($IncludePermissions) {
        Write-Host "`n=== Permissions Details ===" -ForegroundColor Cyan
        foreach ($result in ($allSpResults | Sort-Object LastSignInDateTime -Descending)) {
            Write-Host "`n$($result.ServicePrincipalName) ($($result.AppId)):" -ForegroundColor White
            Write-Host "  Last Sign-In: $($result.LastSignInDateTime)" -ForegroundColor Gray
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
    }
    
    # Export if path specified
    if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        $allSpResults | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
        
        if (Test-Path $ExportPath) {
            $fileInfo = Get-Item $ExportPath
            Write-Host "  File size: $($fileInfo.Length) bytes" -ForegroundColor Gray
        }
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total service principals with sign-in history: $($allSpResults.Count)"
    
    # Count by activity type
    $withAppCredential = ($allSpResults | Where-Object { $_.LastAppCredentialSignIn }).Count
    $withManagedIdentity = ($allSpResults | Where-Object { $_.LastManagedIdentitySignIn }).Count
    $withDelegated = ($allSpResults | Where-Object { $_.LastDelegatedClientSignIn -or $_.LastDelegatedResourceSignIn }).Count
    
    Write-Host "  With App Credential sign-ins: $withAppCredential"
    Write-Host "  With Managed Identity sign-ins: $withManagedIdentity"
    Write-Host "  With Delegated sign-ins: $withDelegated"
}

# Optionally also show recent sign-in activity from audit logs
Write-Host "`n=== Recent Sign-In Activity (Last $Days Days) ===" -ForegroundColor Cyan
$startDate = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)
Write-Host "Querying sign-in logs since $startDate..." -ForegroundColor Yellow

try {
    $filter = "signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge $startDate"
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([System.Web.HttpUtility]::UrlEncode($filter))&`$top=999"
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
    
    Write-Host "  Retrieved $($signInLogs.Count) sign-in events from the last $Days days" -ForegroundColor Green
}
catch {
    Write-Host "Could not retrieve recent sign-in logs: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Process recent sign-in logs if available (shows additional details like IP, location)
if ($signInLogs -and $signInLogs.Count -gt 0) {
    Write-Host "`nRecent sign-in details (last $Days days):" -ForegroundColor Green
    
    # Group by service principal and get last sign-in
    $groupedSignIns = $signInLogs | Group-Object -Property AppId
    
    $recentResults = foreach ($group in $groupedSignIns) {
        $lastSignIn = $group.Group | Sort-Object { [string]$_.createdDateTime } -Descending | Select-Object -First 1
        
        [PSCustomObject]@{
            ServicePrincipalName  = $lastSignIn.AppDisplayName
            AppId                 = $lastSignIn.AppId
            LastSignInDateTime    = [string]$lastSignIn.createdDateTime
            IPAddress             = $lastSignIn.IPAddress
            Location              = "$($lastSignIn.Location.City), $($lastSignIn.Location.CountryOrRegion)"
            Status                = if ($lastSignIn.Status.ErrorCode -eq 0) { "Success" } else { "Failed: $($lastSignIn.Status.FailureReason)" }
            ResourceDisplayName   = $lastSignIn.ResourceDisplayName
            SignInCount           = $group.Count
        }
    }
    
    $recentResults | Sort-Object LastSignInDateTime -Descending | Format-Table ServicePrincipalName, AppId, LastSignInDateTime, IPAddress, Status, SignInCount -AutoSize
    
    # Export recent activity if path specified
    if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        $recentPath = $ExportPath -replace '\.csv$', '_recent.csv'
        $recentResults | Export-Csv -Path $recentPath -NoTypeInformation -Force
        Write-Host "Recent activity exported to: $recentPath" -ForegroundColor Green
    }
}
else {
    Write-Host "No recent sign-in events found in the last $Days days." -ForegroundColor Yellow
}

Write-Host "`nScript completed." -ForegroundColor Cyan
