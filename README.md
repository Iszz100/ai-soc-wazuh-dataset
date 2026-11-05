# AI SOC Wazuh Dataset

A controlled cybersecurity laboratory for AI-assisted
Security Operations Center (SOC) research.

## Objectives

- Build a reproducible cybersecurity laboratory.
- Monitor Linux endpoints using Wazuh.
- Collect normal and simulated security activities.
- Generate structured ground-truth records.
- Prepare datasets for AI-based security analysis.

## Laboratory Components

| Component | Description |
|---|---|
| Attacker | Ubuntu 26.04 |
| Target | Ubuntu 18.04.6 LTS |
| Monitoring | Wazuh Agent 4.14.6 |
| SIEM | Remote Wazuh Manager |
| Web Application | OWASP Juice Shop |
| Dataset Pipeline | Python |
| Network | 192.168.56.0/24 |

## Project Structure

- configs/
- datasets/
- docs/
- ground-truth/
- logs/
- notebooks/
- payloads/
- reports/
- scripts/
- wazuh-export/

## Chapter Progress

### Chapter 2 - Laboratory Preparation

- [x] Network configuration
- [x] Wazuh Agent registration
- [x] OWASP Juice Shop deployment
- [x] Baseline Nmap scan
- [x] Normal ICMP test
- [x] Normal HTTP test
- [x] SSH authentication detection
- [x] Initial ground-truth collection
- [ ] Final documentation and screenshot review

### Future Chapters

Chapter 3, Chapter 4, and Chapter 5
will be documented in this repository.

## Ground Truth

Location: ground-truth/baseline-actions.jsonl

Format: JSON Lines (JSONL)

## Documentation

- [Chapter 2](docs/bab-2/README.md)
- [Chapter 3](docs/bab-3/)
- [Chapter 4](docs/bab-4/)
- [Chapter 5](docs/bab-5/)

## Security

All experiments are conducted in an authorized,
controlled laboratory environment.

Sensitive configurations, passwords, and credentials
must not be committed to this repository.

## Project Status

Research and dataset development are ongoing.
