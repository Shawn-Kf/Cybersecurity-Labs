param ([string]$TargetUser)
$Excluded = @("Administrator", "Guest", "krbtgt")
if ($TargetUser -and ($Excluded -notcontains $TargetUser)) {
    Disable-ADAccount -Identity $TargetUser
}