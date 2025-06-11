# Azure-tags-to-MDE
💡 A PowerShell script to add Azure tags to MDE tags</br>

This script adds Azure tags to MDE tags. It will replace all existing MDE tags. Since Azure tags are key-value pairs and MDE tags are just values, this script uses "key=value" as MDE tags.

Author: Ilkka Hyvönen

## Pre-requisites
1. Hostnames in Azure and MDE need to match.
2. App Registration is required with enought permissions (Defender API Machine.ReadWrite.All and Subscription Reader in Azure)


## Instructions
1. Run AzureTagsToMDE.ps1
