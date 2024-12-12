# Zero Tolerance Domain Resource Tag Audit Process

## Purpose
This document outlines the procedure for auditing Zero Tolerance Domain resource tags in AWS to ensure proper security compliance tagging across all resources.

## Process

### Authentication and Access
Sign in to myapplications.microsoft.com using your corporate credentials. Select the "ODS_SOV_AWS-CONSOLE_PRO" application to access the AWS console. Upon successful authentication, use the provided role-switching link to access the us-security account. Verify your access by confirming "secCompliance@us-security" appears in the top right corner of the AWS console.

### Report Retrieval and Analysis
Navigate to the EC2 Inventory Reports folder using the administrator-provided link. Download the most recent inventory report and open it in Microsoft Excel. Enable filtering across all columns and locate the ZeroToleranceDomain column (typically column E). Apply a filter to display only resources marked as 'yes'.

### Verification and Compliance Check
Conduct a thorough verification by performing a "Find All" search for "zerotolerancedomain: yes". The total number of cells found should match the number of filtered rows, confirming proper tag implementation. For any resources with missing tags, identify the responsible team through the "sbna:platform-governance:owner-team" tag value.

### Remediation
When tag discrepancies are identified, contact the owner team documented in the platform-governance tag. If necessary, escalate through account owners or the Cloud Landing Zone team (CloudLZ@santander.us) to ensure proper tag implementation.

## Support
For assistance with this process or escalation needs, contact the Cloud Landing Zone team at CloudLZ@santander.us.
