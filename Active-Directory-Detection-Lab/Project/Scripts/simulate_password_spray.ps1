# Password Spraying Simulation Script
$users = @("jdoe", "jsmith", "svc_sql", "baduser1", "baduser2")
foreach ($u in $users) {
    net use \\127.0.0.1\IPC$ /user:soclab\$u "WrongPass123!" 2>$null
}