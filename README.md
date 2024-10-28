# Folder Permissions Checker

## Overview

**Folder Permissions Checker** is a PowerShell script designed to help administrators and users audit folder permissions within a specified directory. The script scans through the target directory (and optionally its subdirectories) to identify and list folders where a specified Active Directory (AD) user or group does **not** have any permissions. This tool is invaluable for ensuring proper access controls and maintaining security compliance within your file system.

## Features

- **Interactive Prompts:** Guides users through inputting the necessary information without requiring command-line parameters.
- **AD User/Group Validation:** Validates the provided AD user or group by resolving their Security Identifier (SID).
- **Recursive Scanning:** Option to include nested subdirectories in the scan.
- **Progress Indicator:** Displays real-time progress during the scanning process.
- **Export Results:** Option to export the list of folders without access to a CSV file for further analysis or record-keeping.
- **Error Handling:** Provides informative messages for common issues, such as invalid paths or unresolved identities.

## Prerequisites

- **Operating System:** Windows with PowerShell installed.
- **PowerShell Version:** 5.1 or later.
- **Permissions:** Ensure you have the necessary permissions to read Access Control Lists (ACLs) on the target directories.
- **Active Directory:** Access to resolve AD user or group identities.

## Installation

1. **Download the Script:**
   - Save the script to a directory of your choice, e.g., `C:\Scripts\CheckFolderPermissions.ps1`.

2. **Set Execution Policy:**
   - Ensure that your PowerShell execution policy allows running scripts. You can set it by opening PowerShell as an administrator and executing:
     ```powershell
     Set-ExecutionPolicy RemoteSigned
     ```
   - For more details, refer to [About Execution Policies](https://docs.microsoft.com/powershell/module/microsoft.powershell.security/about/about_execution_policies).

## Usage

1. **Open PowerShell:**
   - Launch PowerShell with appropriate permissions (Run as Administrator if necessary).

2. **Navigate to the Script Directory:**
   ```powershell
   cd C:\Scripts