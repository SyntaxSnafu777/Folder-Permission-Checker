<#
.SYNOPSIS
    Checks folders for permissions and lists those where a specified user or group does not have any permissions.

.DESCRIPTION
    This script prompts the user to input a directory path, an AD user or group, and whether to include nested subdirectories.
    It then scans the specified directories and lists folders where the user or group lacks any permissions.

.PARAMETER None
    This script does not take any parameters. All inputs are prompted interactively.

.EXAMPLE
    Run the script and follow the prompts to check folder permissions.

.NOTES
    - Requires PowerShell 5.1 or later.
    - Ensure you have the necessary permissions to read ACLs on the target directories.
#>

# Function to Resolve User or Group SID
function Get-IdentitySID {
    param (
        [string]$Identity
    )
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($Identity)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.Value
    } catch {
        Write-Error "Unable to resolve SID for identity '$Identity'. Please ensure the name is correct."
        exit 1
    }
}

# Prompt for Directory Path
do {
    $rootPath = Read-Host "Enter the directory path to scan (e.g., E:\Data)"
    if (-not (Test-Path -Path $rootPath -PathType Container)) {
        Write-Host "The path '$rootPath' does not exist or is not a directory. Please try again." -ForegroundColor Red
        $validPath = $false
    } else {
        $validPath = $true
    }
} until ($validPath)

# Prompt for User or Group
do {
    $identity = Read-Host "Enter the AD user or group to check permissions for (e.g., DOMAIN\Domain Users OR DOMAIN\username)"
    if ([string]::IsNullOrWhiteSpace($identity)) {
        Write-Host "Input cannot be empty. Please enter a valid user or group name." -ForegroundColor Red
        $validIdentity = $false
    } else {
        # Attempt to resolve SID to validate the identity
        try {
            $groupSID = Get-IdentitySID -Identity $identity
            $validIdentity = $true
        } catch {
            Write-Host "Failed to resolve '$identity'. Please enter a valid AD user or group." -ForegroundColor Red
            $validIdentity = $false
        }
    }
} until ($validIdentity)

# Prompt to Include Nested Subdirectories
do {
    $includeSubdirs = Read-Host "Do you want to include nested subdirectories? (Y/N)"
    switch ($includeSubdirs.Trim().ToUpper()) {
        "Y" { $recursive = $true; $validChoice = $true }
        "N" { $recursive = $false; $validChoice = $true }
        default {
            Write-Host "Please enter 'Y' for Yes or 'N' for No." -ForegroundColor Yellow
            $validChoice = $false
        }
    }
} until ($validChoice)

# Initialize an array to store folders without user/group access
$foldersWithoutAccess = @()

# Attempt to retrieve directories based on user input
try {
    if ($recursive) {
        $directories = Get-ChildItem -Path $rootPath -Directory -Recurse -ErrorAction Stop
    } else {
        $directories = Get-ChildItem -Path $rootPath -Directory -ErrorAction Stop
    }
} catch {
    Write-Error "Failed to retrieve directories from '$rootPath'. Error: $_"
    exit 1
}

# Add the root directory itself to the scan
$directories += Get-Item -Path $rootPath

# Total number of directories to process
$totalDirectories = $directories.Count
$currentCount = 0

# Iterate through each directory to check ACLs with progress indicator
foreach ($dir in $directories) {
    # Update progress
    $currentCount++
    $percentComplete = [math]::Round(($currentCount / $totalDirectories) * 100, 2)
    
    # Using the -f operator for string formatting to avoid parsing issues
    $statusMessage = "Processing folder {0} of {1}: {2}" -f $currentCount, $totalDirectories, $dir.FullName
    Write-Progress -Activity "Checking Folder Permissions" `
                   -Status $statusMessage `
                   -PercentComplete $percentComplete

    try {
        $acl = Get-Acl -Path $dir.FullName

        # Flag to determine if the user/group has any access rights
        $hasAccess = $false

        foreach ($access in $acl.Access) {
            # Compare using SID for accuracy
            if ($access.IdentityReference -eq $identity -or 
                $access.IdentityReference.Value -eq $groupSID) {
                $hasAccess = $true
                break
            }
        }

        # If the user/group doesn't have access, add to the list
        if (-not $hasAccess) {
            $foldersWithoutAccess += $dir.FullName
        }
    } catch {
        Write-Warning "Unable to access ACL for '$($dir.FullName)'. Error: $_"
    }
}

# Complete the progress bar
Write-Progress -Activity "Checking Folder Permissions" -Status "Completed" -Completed

# Output the results
if ($foldersWithoutAccess.Count -gt 0) {
    Write-Output "`nFolders where '$identity' does NOT have any permissions:`n"
    $foldersWithoutAccess | Sort-Object | ForEach-Object { Write-Output $_ }

    # Prompt to Export Results to CSV
    do {
        $exportChoice = Read-Host "Would you like to export the results to a CSV file? (Y/N)"
        switch ($exportChoice.Trim().ToUpper()) {
            "Y" {
                # Define the output file path with timestamp
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $outputPath = Join-Path -Path $rootPath -ChildPath "FoldersWithoutAccess_$timestamp.csv"

                # Export to CSV
                $foldersWithoutAccess | Sort-Object | Select-Object @{Name='FolderPath';Expression={$_}} | Export-Csv -Path $outputPath -NoTypeInformation
                Write-Host "`nResults have been exported to '$outputPath'." -ForegroundColor Green
                $exported = $true
            }
            "N" {
                Write-Host "Export skipped." -ForegroundColor Yellow
                $exported = $true
            }
            default {
                Write-Host "Please enter 'Y' for Yes or 'N' for No." -ForegroundColor Yellow
                $exported = $false
            }
        }
    } until ($exported)
} else {
    Write-Output "`nAll scanned folders under '$rootPath' grant some permissions to '$identity'."
}
