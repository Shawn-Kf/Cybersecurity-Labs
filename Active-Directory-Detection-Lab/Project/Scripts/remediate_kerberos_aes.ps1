# Enforce AES-128 and AES-256 on svc_sql
Set-ADUser -Identity "svc_sql" -Replace @{"msDS-SupportedEncryptionTypes"=24}
klist purge