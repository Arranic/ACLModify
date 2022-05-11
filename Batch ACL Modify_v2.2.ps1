<#
Title:          Batch ACL Modify
Version:        2.2 (7 Sept 21)
Author:         A1C Robert Griffin, robert.griffin.23@us.af.mil
Co-Author:      Chris Steele, christopher.steele.9.ctr@us.af.mil
Description:    This script modifies the Active Directory ACLs for specific PMO Organizational Units and grants join permissions to the GLS_<BASENAME>_CFP-CSA
                security group that corresponds to the specific base OU.

Change Log:     7 Sept 21 - Added support for additional OUs, changed loop to be a function accepting a singular input
                7 Sept 21 - Added logging
                8 Sept 21 - Added a portion to remove the pre-existing permissions for the OUs so we can start with a fresh set of fully-correct permissions. Also added ability to test script on a single OU.
#>

# Initial variables
$Docs = [Environment]::GetFolderPath("MyDocuments")

# Start log transcription
Start-Transcript -Path "$Docs\ACL_Modify_Log.txt" -IncludeInvocationHeader -Append -NoClobber -Confirm:$false

# Grab all the OUs inside of the PMO OU that we know have missing permissions
$LRAOUs = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=LRA,OU=PMO,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel | Select-Object DistinguishedName,name
$MEDOUs = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Medical Kiosks,OU=PMO,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel | Select-Object DistinguishedName,name
$MITOUs = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=MITs,OU=PMO,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel | Select-Object DistinguishedName,name
$MPSOUs = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=MPS,OU=PMO,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel | Select-Object DistinguishedName,name

# Define and grab a single OU to use for testing
# $TESTOU = Get-ADOrganizationalUnit -Filter {Name -like "Ascension AFB"} -SearchBase "OU=LRA,OU=PMO,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel | Select-Object DistinguishedName,name

# Set GUIDs for the specific ACL Permissions Required for joining to the domain
$ACLPerms = @{
    Reset           = [GUID]::Parse('00299570-246d-11d0-a768-00aa006e0529') # GUID for Reset PW permission
    AcctRestricts   = [GUID]::Parse('4c164200-20c0-11d0-a768-00aa006e0529') # GUID for Account Restrictions Permissions (read/write)
    DNSHostWrite    = [GUID]::Parse('72e39547-7b18-11d1-adef-00c04fd8d5cd') # GUID for DNS Host Write permissions
    SPNWrite        = [GUID]::Parse('f3a64788-5306-11d1-a9c5-0000f80367c1') # GUID for Service Principal Name permissions
    UserAcctControl = [GUID]::Parse('bf967a68-0de6-11d0-a285-00aa003049e2') # GUID for User Account Control Permissions to avoid the following error: "The join operation was not successful. This could be because an existing computer account having name "<computer name>" was previously created using a different set of credentials. Use a different computer name, or contact our administrator to remove any stale conflicting account. The error was: Access is denied."
    AccessRuleType  = [System.Security.AccessControl.AccessControlType]::Allow
    Inheritance     = [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    Computer        = [GUID]::Parse('bf967a86-0de6-11d0-a285-00aa003049e2') # GUID for Computer Objects
    }

Function Write-PermissionProps ([array]$TargetOU) {
    # Iterate through all the OUs and add the ACL rules
    foreach ($OU in $TargetOU) {
        # Get the ACL for the OU
        $ACL = (Get-Acl -Path "AD:\$($OU.DistinguishedName)")
        #Get CFP group
        switch ($ou.name) {
            "Fort Sam Houston AFB" {
                $CFPFltr = "GLS_Fort Sam_CFP-CSA"
                }
            "Gunter AFIN AFB" {
                continue
                #OU needs to be deleted
                }
            "HQ AFRC AFB" {
                $CFPFltr = "GLS_HQ_AFRC_CFP-CSA"
                }
            default {
                $baseName = $ou.name.Replace(" AFB","")
                $CFPFltr = "GLS_$basename`_CFP-CSA"
                }
            }
        $CFPName = Get-ADGroup -Filter {Name -eq $CFPFltr} | Select-Object -ExpandProperty SamAccountName
        $IDRef = [System.Security.Principal.NTAccount] "$CFPName"

        #Remove already existing permissions
        $ACL.Access | where IdentityReference -match $CFPName | foreach {$ACL.RemoveAccessRule($_) | Out-Null}

        # Let's try to create the ACL Permissions
        Try {
            Write-Host "Writing permissions for:" $CFPName -ForegroundColor Cyan
            # Account Restrictions Permissions

            Write-Host "Writing Account Restrictions Perms" -ForegroundColor Green
            $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $IDRef,
                'ReadProperty,WriteProperty',
                $ACLPerms.AccessRuleType,
                $ACLPerms.AcctRestricts,
                $ACLPerms.Inheritance,
                $ACLPerms.Computer
            )))
            # User Account Control Permissions
            Write-Host "Writing User Account Control Perms" -ForegroundColor Green
            $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $IDRef,
                'ReadProperty,WriteProperty',
                $ACLPerms.AccessRuleType,
                $ACLPerms.UserAcctControl,
                $ACLPerms.Inheritance,
                $ACLPerms.Computer
            )))
            # DNS Host Write Permissions
            Write-Host "Writing DNS Host Write Perms" -ForegroundColor Green
            $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $IDRef,
                'Self',
                $ACLPerms.AccessRuleType,
                $ACLPerms.DNSHostWrite,
                $ACLPerms.Inheritance,
                $ACLPerms.Computer
            )))
            # Service Principal Name Permissions
            Write-Host "Writing SPN Perms" -ForegroundColor Green
            $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $IDRef,
                'Self',
                $ACLPerms.AccessRuleType,
                $ACLPerms.SPNWrite,
                $ACLPerms.Inheritance,
                $ACLPerms.Computer
            )))
            # Password Reset Permissions
            Write-Host "Writing Reset Password Perms" -ForegroundColor Green
            $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $IDRef,
                'ExtendedRight',
                $ACLPerms.AccessRuleType,
                $ACLPerms.Reset,
                $ACLPerms.Inheritance,
                $ACLPerms.Computer
            )))

            # Apply the changes to the ACL
            Set-Acl -Path "AD:\$($OU.DistinguishedName)" -AclObject $ACL -Verbose
        }
        Catch {
            # Write the errors in a big bold yellow obnoxious thing
            Write-Host $Error -ForegroundColor Yellow -Separator '                                  
            
            '
            continue
        }
    }
}

Write-PermissionProps $LRAOUs
Write-PermissionProps $MEDOUs
Write-PermissionProps $MITOUs
Write-PermissionProps $MPSOUs

# Run the Test OU
#Write-PermissionProps $TESTOU

# Stop logging the actions
Stop-Transcript