# Bab 2 - Laboratory Preparation and Baseline Testing

## 1. Objective

This chapter documents the preparation of the cybersecurity
laboratory and initial baseline testing.

## 2. Laboratory Components

| Component | Configuration |
|---|---|
| Attacker | Ubuntu 26.04 |
| Target | Ubuntu 18.04.6 LTS |
| Attacker IP | 192.168.56.1 |
| Target IP | 192.168.56.100 |
| Network | 192.168.56.0/24 |
| Wazuh Agent ID | 022 |
| Wazuh Agent Version | 4.14.6 |
| Web Application | OWASP Juice Shop |
| Web Port | TCP/3000 |

## 3. Network Connectivity

ICMP connectivity test:

- 4 packets transmitted.
- 4 packets received.
- 0% packet loss.

Evidence: ../../logs/03-normal-ping.txt

## 4. Network Scanning

Nmap identified the following services:

| Port | State |
|---|---|
| 22/tcp | Open |
| 80/tcp | Closed |
| 3000/tcp | Open |
| 8080/tcp | Closed |

Evidence: ../../logs/02-webapp-scan.txt

## 5. OWASP Juice Shop

OWASP Juice Shop was deployed using Docker.

Image: bkimminich/juice-shop:latest

Port mapping: 192.168.56.100:3000

HTTP verification:
- Status: 200 OK

Evidence: ../../logs/04-normal-web-access.txt

## 6. Time Synchronization

Attacker and target systems were configured
to use the Asia/Jakarta timezone.

NTP synchronization was enabled.

Evidence: ../../logs/time-sync-comparison.txt

## 7. Normal Activity Collection

The following activities were recorded:

| Activity | Label |
|---|---|
| ICMP ping | normal |
| HTTP GET | normal |
| SSH login success | normal |

Ground truth:
../../ground-truth/baseline-actions.jsonl

## 8. Wazuh Monitoring

Observed endpoint:

- Agent ID: 022
- Agent name: luis_ubuntuSOCAI
- Operating system: Ubuntu 18.04 LTS
- Agent version: 4.14.6
- Status: Active

SSH authentication success was detected.

Rule ID: 5715

Description: sshd: authentication success.

The exact correlation between individual SSH events
and ground-truth timestamps still requires verification.

## 9. Collected Evidence

- Baseline Nmap scan
- Web application scan
- ICMP connectivity test
- HTTP access test
- Time synchronization comparison
- Ground-truth JSONL records
- Wazuh Threat Hunting events

## 10. Remaining Tasks

- [ ] Verify fresh SSH event correlation.
- [ ] Capture laboratory screenshots.
- [ ] Review all evidence.
- [ ] Finalize Chapter 2 documentation.

## 11. Chapter Status

Laboratory preparation and initial baseline testing
have been performed.

Final evidence review remains before Chapter 2
can be declared complete.
