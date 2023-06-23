# List of all approved users
$admins = @("administrator","ashepard", "asteele", "yafoloyan", "gmctaggart", "sprice", "tviktorov")
$users = @("telwes", "rekin", "pqadir", "bwallis", "tmac", "ysommer", "jgust", "aelliston", "jallaway", "mbyrd", "hdirks", "emiddlesworth",
            "vfederov", "tlayton", "givanow", "nmartin", "nholmes", "bsalamanca", "lpaddon", "dcalvo")
[System.Collections.ArrayList]$allUsers = $admins + $users
$allUsers.Remove("administrator")

# Ask the password you want to set for all accounts
$password = Read-Host -AsSecureString

# List of computer users and Admins
$compAdmin = (Get-LocalGroupMember Administrators).Name -replace ".*\\"
$compAllUsers = (Get-LocalUser).Name

# Check if all Aprroved users have a account on this system. If not then create a new one.
foreach ($i in  $allUsers){
    if ($i -notin $compAllUsers){
        "!! Creating new user $i"
        $null = $i | New-LocalUser -Password $password
    }
}
# Check if all System users are approved or not. If not then they are deleted.
foreach ($i in $compAllUsers){
    if ($i -eq "Administrator" -or $i -eq "DefaultAccount" -or $i -eq "Guest" -or $i -eq "WDAGUtilityAccount"){
        "*** Cannot Delete $i"
        "!!! Disabling $i"
        Disable-LocalUser $i
    }
    elseif ($i -notin $allUsers){
        "!!!! Deleting unapproved user $i"
        $i | Remove-LocalUser
        }
}
# Checks if the Approved Admins have access to the system. If not then it adds them to the Admin group.
Foreach($i in $admins){
    if ($i -notin $compAdmin) {
        "!! ADDING $i to the Admin group!"
        Add-LocalGroupMember -Group "Administrators" -Member "$i"
    }
}
# Checks the computer if the existing admins should be an admin or not. If not then it removes them.
# WHAT DO WE DO WITH THE ADMINISTRATOR ACCOUNT?
Foreach($i in $compAdmin){
    if ($i -notin $admins) {
        "!! Removing $i from the Admin Group"
        Remove-LocalGroupMember -Group "Administrators" -Member "$i"
    }
}

# Set Passowrd for allUsers and PasswordNeverExpires to false
Foreach ($i in $allUsers){
    $i | Set-LocalUser -Password $password -PasswordNeverExpires $false
}

# Setting localpolicies-audit policies
auditpol /set /category:"Account Logon" /success:disable
auditpol /set /category:"Account Logon" /failure:enable
auditpol /set /category:"Account Management" /success:enable
auditpol /set /category:"Account Management" /failure:disable
auditpol /set /category:"DS Access" /success:disable
auditpol /set /category:"DS Access" /failure:disable
auditpol /set /category:"Logon/Logoff" /success:disable
auditpol /set /category:"Logon/Logoff" /failure:enable
auditpol /set /category:"Object Access" /success:disable
auditpol /set /category:"Object Access" /failure:disable
auditpol /set /category:"Policy Change" /success:enable
auditpol /set /category:"Policy Change" /failure:disable
auditpol /set /category:"Privilege Use" /success:enable
auditpol /set /category:"Privilege Use" /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable
auditpol /set /category:"Detailed Tracking" /failure:enable
auditpol /set /category:"System" /success:disable
auditpol /set /category:"System" /failure:enable