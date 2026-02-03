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
    [string]$ExportPath
)

# Required Graph API permissions
$requiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All"
)

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

# Calculate the date filter
$startDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "`nRetrieving service principal sign-ins from the last $Days days..." -ForegroundColor Yellow

try {
    # Get service principal sign-in logs
    $signInLogs = Get-MgAuditLogSignIn -Filter "signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge $startDate" -All -ErrorAction Stop
    
    if (-not $signInLogs -or $signInLogs.Count -eq 0) {
        # Try alternative approach - get from service principal sign-in logs endpoint
        Write-Host "Trying alternative endpoint for service principal sign-ins..." -ForegroundColor Yellow
        
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge $startDate"
        $signInLogs = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        
        if ($signInLogs.value) {
            $signInLogs = $signInLogs.value
        }
    }
}
catch {
    Write-Host "Using beta endpoint for managed identity and service principal sign-ins..." -ForegroundColor Yellow
    
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
            
            if ($ExportPath) {
                $results | Export-Csv -Path $ExportPath -NoTypeInformation
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
        
        [PSCustomObject]@{
            ServicePrincipalName = $lastSignIn.AppDisplayName
            AppId                = $lastSignIn.AppId
            LastSignInDateTime   = $lastSignIn.CreatedDateTime
            IPAddress            = $lastSignIn.IPAddress
            Location             = "$($lastSignIn.Location.City), $($lastSignIn.Location.CountryOrRegion)"
            Status               = if ($lastSignIn.Status.ErrorCode -eq 0) { "Success" } else { "Failed: $($lastSignIn.Status.FailureReason)" }
            ResourceDisplayName  = $lastSignIn.ResourceDisplayName
            SignInCount          = $group.Count
        }
    }
    
    # Display results
    Write-Host "`n=== Last Sign-In Activity per Service Principal ===" -ForegroundColor Cyan
    $results | Sort-Object LastSignInDateTime -Descending | Format-Table -AutoSize
    
    # Export if path specified
    if ($ExportPath) {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
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
            [PSCustomObject]@{
                AppId                          = $sp.appId
                ServicePrincipalId             = $sp.id
                LastSignInDateTime             = $sp.lastSignInActivity.lastSignInDateTime
                LastSignInRequestId            = $sp.lastSignInActivity.lastSignInRequestId
                DelegatedClientSignIn          = $sp.delegatedClientSignInActivity.lastSignInDateTime
                DelegatedResourceSignIn        = $sp.delegatedResourceSignInActivity.lastSignInDateTime
                ApplicationCredentialSignIn    = $sp.applicationAuthenticationClientSignInActivity.lastSignInDateTime
                ManagedIdentitySignIn          = $sp.applicationAuthenticationManagedIdentitySignInActivity.lastSignInDateTime
            }
        }
        
        Write-Host "`nService Principal Sign-In Activities:" -ForegroundColor Green
        $spResults | Sort-Object LastSignInDateTime -Descending | Format-Table -AutoSize
        
        if ($ExportPath) {
            $detailedPath = $ExportPath -replace '\.csv$', '_detailed.csv'
            $spResults | Export-Csv -Path $detailedPath -NoTypeInformation
            Write-Host "Detailed results exported to: $detailedPath" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "Note: Detailed service principal activity endpoint not available or requires additional permissions." -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

Write-Host "`nScript completed." -ForegroundColor Cyan
