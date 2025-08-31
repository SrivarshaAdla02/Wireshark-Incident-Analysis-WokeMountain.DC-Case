# Wireshark-Incident-Analysis-WokeMountain.DC-Case

📌 Project Overview

This project documents the forensic analysis of a network breach using Wireshark PCAP investigation techniques.
The case study centers on an infection of host 10.1.21.101 within the wokemountain.com domain, leading to multi-family malware activity involving Zeus/Zbot, Gozi, and Ursnif.

The investigation highlights:

Evidence collection from raw packet captures

Detection of staged malware payloads

Identification of encrypted command-and-control (C2) traffic

Abuse of Active Directory replication (DCSync attack – MITRE T1003.006)

Root cause analysis and remediation steps

⚡ Key Findings

Initial Infection: Raw HTTP GET request delivered a .bin config file consistent with Zeus/Zbot.

Payload Delivery: Multiple binaries disguised as .jpg or .ico, but contained MZ headers (Windows PE executables).

C2 Traffic: TLS sessions masked as Microsoft services via SNI fronting (e.g., iecvlist.microsoft.com).

Credential Theft: Unauthorized DRSUAPI replication (DCSync) leveraged ZeroLogon (CVE-2020-1472) against the DC.

Reconnaissance: DNS queries to myip.opendns.com used to discover public IP.

Obfuscation Techniques: Randomized URIs, fake MIME types, SNI spoofing, and staged loaders <1 MB.

🛠️ Methodology

Isolated infected machine in Kali Linux VM for safe analysis

Captured snapshots + PCAP evidence (never executed binaries)

Cross-referenced Suricata IDS alerts with Wireshark packet data

Extracted file hashes, domains, and IPs for Threat Intel lookups

Validated findings against VirusTotal & Abuse.ch JA3 fingerprints

📂 Evidence Highlights
Indicators of Compromise (IOCs)

IPs

209.141.51.196  (/Lk9tdZ, /files/1.bin)
185.186.244.130 (greatewallfirewall[.]xyz)
72.21.81.200    (Gozi C2 – TLS JA3 match)
193.239.84.250  (Zeus Panda infrastructure)
184.252.95.102  (Ursnif malware)
208.67.222.222  (OpenDNS – myip.opendns.com lookup)
162.0.224.165   (grab32.rar – staging attempt)


Domains

greatewallfirewall[.]xyz
iecvlist.microsoft.com (spoofed SNI)
myip.opendns[.]com

Hashes

e78286d0f5dfa2c85615d11845d1b29b0bfec227bc077e74cb1ff98ce8df4c5a (favicon.ico)
cde859855eefdc66a7d3c24bd0577b8dbfcc12ed5e404f0fdf7cc9fef5393f85 (Tj4t.yml)

🛡️ Corrective Actions

Isolate & reimage compromised host (DESKTOP-NB72TZA)

Block all listed IOCs at firewall/EDR level

Reset all AD passwords, enforce Kerberos ticket invalidation

Monitor RPC/DRSUAPI calls between non-DC and DC hosts

Enable auditing & EDR logging for unauthorized replication

🔬 MITRE ATT&CK Mapping

T1003.006 – OS Credential Dumping: DCSync

T1071.001 – Application Layer Protocol: Web Protocols (HTTP C2)

T1573 – Encrypted Channel (TLS SNI Fronting)

T1105 – Ingress Tool Transfer (Payload Delivery)

📊 Project Impact

This case study demonstrates:

How malware blends with legitimate Microsoft traffic to evade detection

The importance of PCAP-based investigation for uncovering credential theft

Practical use of Wireshark filters (http, ssl, frame contains "MZ", drsuapi) in real-world analysis

👤 Author

Sri Varsha Adla

🚨 Disclaimer

This repository is strictly for educational & research purposes.
All malicious samples were analyzed in a controlled lab environment.
