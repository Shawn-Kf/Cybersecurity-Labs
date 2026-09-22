User: admin

Password: ciwlmoLahwcIjjHGzgk9gYMqWj4zogr+ 

## Phase 1.2: Wazuh SIEM Deployment & Verification
- Extended Ubuntu LVM root volume to allocate full 50GB virtual disk.
- Deployed Wazuh 4.9 All-in-One stack (Indexer, Manager, Dashboard) with `--ignore-limits` flag to accommodate 3GB RAM allocation.
- Verified active state of all core services (`wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard`).
- Configured host NAT port forwarding (8443 -> 443) for isolated host-only browser access.
- Baseline dashboard confirmed accessible at https://localhost:8443.
- Configured `/var/ossec/etc/ossec.conf` with `<logall_json>yes</logall_json>` for raw archive indexing.
- Verified daemon listener sockets: Port 1514 (Agent Telemetry Ingestion) and Port 1515 (Agent Auth/Enrollment Service).
- Configured static IP `10.0.2.10/24` with default gateway `10.0.2.1` and loopback DNS.
- Renamed host to `AD-DC01`.
- Installed AD DS binaries and promoted machine to primary Domain Controller for `soclab.local`.
- Deployed Sysmon with SwiftOnSecurity configuration onto Domain Controller (`AD-DC01`).
- Enabled granular auditing for Process Creation (with full CLI arguments) and Logon/Auth events.
- Successfully registered Wazuh Agent to Wazuh Manager over Port 1515/1514 and verified operational data ingestion.