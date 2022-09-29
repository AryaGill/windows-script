# List of all approved users 
$allUsers = @("ashepard", "asteele", "yafoloyan", "gmctaggart", "sprice", "tviktorov","telwes", "rekin", "pqadir", "bwallis", "tmac", "ysommer", "jgust", "aelliston", "jallaway", "mbyrd", "hdirks", "emiddlesworth",
            "vfederov", "tlayton", "givanow", "nmartin", "nholmes", "bsalamanca", "lpaddon", "dcalvo")
$admins = @("administrator","ashepard", "asteele", "yafoloyan", "gmctaggart", "sprice", "tviktorov") # WHAT DO WE DO WITH THE ADMINISTRATOR ACCOUNT?
$users = @("telwes", "rekin", "pqadir", "bwallis", "tmac", "ysommer", "jgust", "aelliston", "jallaway", "mbyrd", "hdirks", "emiddlesworth",
            "vfederov", "tlayton", "givanow", "nmartin", "nholmes", "bsalamanca", "lpaddon", "dcalvo")
# Ask the password you want to set for all accounts
$password = Read-Host -AsSecureString
            
# List of computer admins
$compAdmin = (Get-LocalGroupMember Administrators).Name -replace ".*\\"
$compAllUsers = (Get-LocalUser).Name -replace "Administrator" -replace "DefaultAccount" -replace "WDAGUtilityAccount"

# Set Passowrds for all users
#net user ashepard CyberPatri0ts!
#net user asteele CyberPatri0ts!
#net user yafoloyan CyberPatri0ts!
#net user gmctaggart CyberPatri0ts!
#net user sprice CyberPatri0ts!
#net user tviktorov CyberPatri0ts!

# Check if all Aprroved users have a account on this system. If not then create a new one. 
foreach ($i in  $allUsers){
    if ($i -notin $compAllUsers){
        "!! Creating new user $i"
        $null = $i | New-LocalUser -Password $password
    }
}
# Check if all System users are approved or not. If not then they are deleted. 
foreach ($i in $compAllUsers){
    if ($i -notin $allUsers){
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