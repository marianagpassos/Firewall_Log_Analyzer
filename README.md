# Firewall_Log_Analyzer
The Firewall Log Analyzer is a forensic analysis and security monitoring tool developed in Python. The system processes firewall logs, identifies attack patterns, and generates detailed reports with mitigation methodologies.

Developed as a personal project to demonstrate skills in:

- Python (OOP, data structures, log processing)
- Cybersecurity (intrusion detection, forensic analysis)
- Data visualization (interactive HTML reports)
- Unit testing and best practices

## Features ✨

### Threat Detection
- **SSH Brute Force** – Multiple failed login attempts on port 22.
- **Port Scanning** – Sequential port scans from a single source.
- **External NetBIOS** – Legacy protocol traffic from public IPs.
- **SMB Exploitation** – Attempts to access port 445 (EternalBlue, etc.).
- **ICMP Sweep** – Network mapping (reconnaissance phase).

### General Features
- Structured log parser with timestamp normalisation.
- Temporal analysis with configurable sliding windows.
- Export incidents to CSV.
- Visual HTML reports with severity colour coding and mitigation guidance.
- Realistic log generator for testing.
- Mitigation methodologies (Prevention, Detection, Response) included per incident.
- Supports analysis of any historical log file (batch mode).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/marianagpassos/Firewall_Log_Analyzer.git
   cd Firewall_Log_Analyzer


# Usage 💻
Basic Commands
Generate sample logs

<pre> python main.py --generate </pre>

# Analyze logs (default file)
<pre> python main.py --analyze </pre>

# Analyze a specific file
<pre> python main.py --analyze --file my_logs.txt </pre>

# Generate 100 sample logs
<pre> python main.py --generate --num 50 </pre>

# Analyze without generating HTML
<pre> python main.py --analyze --no-html </pre>

# Log Format - The analyzer expects logs in the following format :
<pre> YYYY-MM-DD HH:MM:SS | firewall_ip | action | protocol | src_ip:port | dst_ip:port | message </pre>

-Action : `allow` or `deny` ;  Protocol : e.g., `tcp`, `udp`;  Source : `src_ip:port`;  Destination : `dst_ip:port`

## Example 
 <pre> 2024-05-27 09:30:15 | 192.168.1.1 | deny | tcp | 203.0.113.10:54321 | 10.0.0.5:22 | Password failed for root </pre>




# Detected Attacks 🎯
## 1. SSH Brute Force Attack
Description: Multiple failed SSH authentication attempts from the same IP address within a short period of time.

Criteria:
- 3+ failed attempts in 60 seconds (configurable)
- Destination port 22 (SSH)
- Message contains "failed password"

Log example:
<pre> 2024-05-27 09:30:15 | 192.168.1.1 | deny | tcp | 203.0.113.10:54321 | 10.0.0.5:22 | Failed password for admin </pre>
<pre> 2024-05-27 09:30:16 | 192.168.1.1 | deny | tcp | 203.0.113.10:54322 | 10.0.0.5:22 | Failed password for root </pre>
<pre> 2024-05-27 09:30:17 | 192.168.1.1 | deny | tcp | 203.0.113.10:54323 | 10.0.0.5:22 | Failed password for user </pre>


##2. Port Scanning
Description: Scanning multiple ports on the same host, indicating reconnaissance.

Criteria:
- 3+ different ports within 60 seconds
- Same source IP address
- Message contains "port scan"

Log example:
<pre> 2026-02-15 09:30:24 | 192.168.1.1 | deny | tcp | 198.51.100.20:17885 | 10.0.0.6:79 | Port Scan detected: Sequential ports </pre>


## 3. External NetBIOS Traffic
Description: NetBIOS traffic (legacy protocol) originating from external IP addresses.

Criteria:
- UDP protocol
- Non-private source IP address
- Message contains "netbios"

Log example:
<pre> 2026-02-15 09:30:46 | 192.168.1.1 | deny | udp | 45.33.22.11:11111 | 192.168.1.255:137 | NetBIOS Name Query broadcast - Suspicious external source </pre>


## 4. SMB Exploitation Attempt
Description: Attempts to access the SMB port (445) from external sources, frequently associated with ransomware.

Criteria:
- Destination port 445
- Non-private source IP address
- Message contains "smb"


Log example:
<pre> 2026-02-15 09:32:04 | 192.168.1.1 | deny | tcp | 198.51.100.30:44000 | 192.168.1.200:445 | SMB exploitation attempt - EternalBlue signature </pre>

## 5. ICMP Scan
Description: Network scan using ICMP (ping) to map active hosts.

Criteria:
- 3+ different targets within 60 seconds
- ICMP protocol
- Message contains "icmp sweep"

Log example:
<pre> 2026-02-15 09:31:08 | 192.168.1.1 | deny | icmp | 45.33.22.20:0 | 10.0.0.1:0 | ICMP Sweep detected </pre>



# Development 🛠️
## Future Improvements
- [ ] Support for more log formats (JSON)
- [ ] Detection of new attacks
- [ ] Machine learning for anomalies
- [ ] Real-time dashboard


# Author 👤
## Mariana Passos
- 🎓 Bachelor's Degree in Telecommunications and Computer Engineering
- 🐱 GitHub: @marianagpassos
