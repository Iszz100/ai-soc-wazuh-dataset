# AI SOC Wazuh Dataset

A controlled laboratory project for building an AI Security Operations Center (AI SOC) training dataset using Wazuh, Kali Linux, Python, and local AI assistance.

The project follows the technical workflow described in:

**AI SOC Mastery: Menyiapkan Script Pentest untuk Membuat Dataset Training AI di WAZUH**
Author: Onno W. Purbo (2026)

---

## 1. Project Overview

This project focuses on transforming controlled penetration-testing activities into structured and auditable security datasets for AI SOC research.

Instead of relying only on publicly available datasets, this project builds its own data through authorized laboratory scenarios.

The workflow combines:

- Controlled security testing in an isolated laboratory.
- Ground truth generation using JSONL.
- Wazuh security event and alert collection.
- Reconnaissance and vulnerability scanning.
- Authentication and web attack simulation.
- Safe payload generation using a local Large Language Model.
- Dataset validation, labeling, and quality reporting.
- AI SOC dataset preparation.

The main principle is:

**Scripts execute scenarios. Ground truth records the expected activity. Wazuh captures security signals. Python builds the dataset. AI assists with analysis and dataset engineering.**

---

## 2. Project Objectives

The main objectives are:

1. Build an isolated and reproducible Wazuh laboratory.
2. Generate controlled normal and suspicious security events.
3. Record scenario activities using structured ground truth.
4. Collect and understand Wazuh alerts and archives.
5. Correlate ground truth with observed Wazuh events.
6. Create structured and consistently labeled datasets.
7. Use local AI to generate safe dummy payload variations.
8. Develop custom Wazuh decoders and detection rules.
9. Automate scenario execution and evidence collection.
10. Prepare datasets for AI/ML experimentation.

---

## 3. Laboratory Scope and Safety

All experiments are intended for an authorized and isolated laboratory environment.

Safety principles:

- Only use systems owned by the researcher or explicitly authorized for testing.
- Use private laboratory network addresses.
- Do not target public systems.
- Do not use real credentials or sensitive tokens.
- Use dummy accounts and dummy payloads.
- Avoid destructive payloads and unauthorized access.
- Validate scripts before executing laboratory scenarios.
- Keep sensitive raw Wazuh exports and environment-specific evidence out of public Git.

The purpose of the simulations is to generate security evidence, not to damage systems.

---

## 4. Technology Stack

| Technology | Purpose |
|---|---|
| Wazuh | Security monitoring and event collection |
| Kali Linux / Ubuntu | Laboratory CLI environment |
| Python | Automation and dataset engineering |
| Bash | Command-line automation |
| Docker | Laboratory application and service deployment |
| Nmap | Network reconnaissance |
| curl | HTTP inspection and web interaction |
| WhatWeb | Web fingerprinting |
| Nikto | Web server assessment |
| Nuclei | Controlled vulnerability scanning |
| Ollama | Local LLM runtime |
| Qwen3:4b | Local AI model used in Chapter 6 |
| jq | JSON inspection and processing |
| Git / GitHub | Version control and documentation |
| Pandas / Scikit-learn / PyArrow | Dataset processing and ML workflow |

Tools are introduced according to the relevant chapter requirements.

---

## 5. Dataset Workflow

The project follows this general pipeline:

```text
Isolated Laboratory
        |
        v
Controlled Pentest Scenarios
        |
        v
Ground Truth JSONL
        |
        v
Wazuh Agent and Manager
        |
        +------> alerts.json
        |
        +------> archives.json
        |
        v
Ground Truth and Wazuh Correlation
        |
        v
Data Cleaning and Normalization
        |
        v
Dataset Labeling and Validation
        |
        v
Final Dataset
        |
        v
AI/ML Baseline and Evaluation
        |
        v
AI-Assisted SOC Report
```

Local AI is also used to assist with safe dummy payload generation and scenario variation.

Generated scenario plans are distinguished from actual events observed by Wazuh.

---

## 6. Chapter Documentation and Progress

The chapter structure below follows the original book's table of contents.

### Chapter 1 — Konsep AI SOC Dataset: Dari Pentest ke Training Data

**Status: Completed**

Topics:
- Why SOC organizations need their own datasets.
- Transforming penetration testing into AI training data.
- Understanding events, alerts, incidents, ground truth, and labels.
- Threat taxonomy for Wazuh datasets.
- Legal, ethical, and isolated laboratory principles.
- Overall AI SOC architecture.
- Characteristics of a high-quality dataset.

### Chapter 2 — Membangun Lab Wazuh dan Kali Linux yang Siap Menghasilkan Dataset

**Status: Completed**

Topics:
- Minimum laboratory design.
- Laboratory network topology.
- Installation of essential CLI tools.
- Dataset project directory structure.
- Wazuh server and agent configuration.
- Understanding alerts.json and archives.json.
- Log retention.
- Time synchronization.
- Normal traffic baseline.

### Chapter 3 — Desain Ground Truth dan Schema Dataset Training AI

**Status: Completed**

Topics:
- Why ground truth is more important than alerts.
- Ground truth JSONL format.
- Dataset labeling and taxonomy.
- MITRE ATT&CK mapping.
- Final dataset schema.
- Field normalization.
- Dataset versioning.

Repository outputs include:
- Ground truth schemas.
- Dataset schemas.
- Label taxonomy.
- MITRE mapping.
- Ground truth generation scripts.
- Wazuh alert normalization.
- Dataset card and initial versioning.

### Chapter 4 — Script Reconnaissance dan Vulnerability Scanning untuk Dataset

**Status: Completed**

Topics:
- Safe reconnaissance principles.
- Nmap-based reconnaissance.
- Web fingerprinting using curl, WhatWeb, Nikto, and Nuclei.
- Recon script wrapper.
- Scenario intensity variation.
- Wazuh correlation.
- Result validation.

The purpose is to generate controlled laboratory reconnaissance events that can be correlated with ground truth.

### Chapter 5 — Script Simulasi Authentication dan Web Attack di Lab

**Status: Completed**

Topics:
- Controlled attack simulation principles.
- SSH login failure.
- Web login failure.
- Web input attack.
- File Integrity Monitoring events.
- Suspicious command logging.
- Script safety guards.

The simulations use dummy credentials, controlled targets, and safe execution limits.

### Chapter 6 — Menggunakan AI Lokal untuk Membuat Random Payload Aman dan Variasi Skenario

**Status: Completed**

Topics:
- Role of AI in dataset generation.
- Local LLM using Ollama.
- Safe payload generation prompts.
- Randomization engine.
- Payload validation.
- Dataset payload catalog.
- Avoiding an unrealistically perfect dataset.

Implementation results:

| Artifact | Result |
|---|---:|
| AI-generated approved payloads | 19 |
| Rejected AI payloads | 1 |
| Manual payload entries | 3 |
| Merged payload catalog | 22 |
| Random scenario plan | 30 |
| Mixed scenario noise | 50 |
| Python scripts compiled | 5 |
| Merged catalog validation errors | 0 |

Key repository artifacts:

```text
prompts/
    safe_payload_generator.prompt.txt

payloads/
    payload_catalog.jsonl
    payload_catalog_manual.jsonl
    payload_catalog_merged.jsonl
    wordlist_dummy.json
    scenario_plan.jsonl
    mixed_scenario_noise.jsonl

scripts/
    ollama_payload_generator.py
    validate_payload_catalog.py
    random_scenario_builder.py
    payload_catalog_summary.py
    mixed_scenario_noise.py

logs/
    chapter6/
        ollama_raw_response.txt

reports/
    chapter6/
        payload_validation_report.json
        payload_validation_merged_report.json
        payload_catalog_summary.md
```

The generated plans are dataset preparation artifacts and are not presented as actual Wazuh-detected events.

### Chapter 7 — Custom Decoder, Custom Rule, dan Wazuh Logtest untuk Dataset

**Status: Not Started**

Planned topics:
- Reading alerts.json and archives.json.
- Custom JSON logs from pentest scripts.
- Custom Wazuh decoders.
- Custom Wazuh rules.
- Testing using Wazuh Logtest.
- Rule quality checklist.

### Chapter 8 — Automation CLI: Menjalankan Skenario, Mengumpulkan Log, dan Membuat Evidence

**Status: Not Started**

Planned topics:
- Pentest dataset orchestrator.
- Bash automation.
- Python automation.
- Cron and scheduled dataset generation.
- Wazuh log export.
- Evidence pack generation.
- Error handling.

### Chapter 9 — Preprocessing, Labeling, dan Validasi Dataset AI SOC

**Status: Not Started**

Planned topics:
- Reading large JSONL files.
- Ground truth and Wazuh alert correlation.
- Dataset cleaning.
- Feature engineering.
- Final labeling.
- Dataset quality validation.
- Dataset output formats.

Expected formats include CSV, JSONL, and Parquet.

### Chapter 10 — Mini Project: Dataset Training AI Wazuh End-to-End

**Status: Not Started**

Planned topics:
- End-to-end dataset pipeline.
- Simple baseline model.
- Model evaluation.
- AI-assisted SOC reporting.
- Safe dataset publication.
- Professional CEH/SOC checklist.
- Further development roadmap.

---

## 7. Repository Structure

Current repository organization:

```text
ai-soc-wazuh-dataset/
|
|-- configs/
|-- datasets/
|-- docs/
|-- ground-truth/
|-- logs/
|-- notebooks/
|-- payloads/
|-- prompts/
|-- reports/
|-- schemas/
|-- scripts/
|-- wazuh-export/
|
|-- README.md
```

### Directory Purposes

| Directory | Purpose |
|---|---|
| configs/ | Dataset and laboratory configuration |
| datasets/ | Dataset artifacts and dataset cards |
| docs/ | Project and chapter documentation |
| ground-truth/ | Ground truth scenario records |
| logs/ | Laboratory and script execution logs |
| notebooks/ | Dataset exploration and analysis |
| payloads/ | Dummy payloads, wordlists, and scenario plans |
| prompts/ | Safe prompts for local AI generation |
| reports/ | Validation and experiment reports |
| schemas/ | JSON schemas for structured data |
| scripts/ | Python and Bash automation scripts |
| wazuh-export/ | Wazuh alert and archive export artifacts |

Additional directories will be introduced when required by subsequent chapters.

---

## 8. Dataset Publication Policy

This repository is intended to provide reproducible code, safe sample data, schemas, and technical documentation.

Sensitive raw Wazuh events and environment-specific laboratory information are retained locally when necessary.

Public repository contents must not expose:

- Real credentials.
- Authentication tokens.
- Private keys.
- Sensitive internal network information.
- Unsanitized security logs.
- Confidential laboratory evidence.

Only reviewed and appropriate artifacts should be committed.

---

## 9. Current Project Progress

| Chapter | Subject | Status |
|---|---|---|
| 1 | AI SOC Dataset Concepts | Completed |
| 2 | Wazuh and Kali Linux Lab | Completed |
| 3 | Ground Truth and Dataset Schema | Completed |
| 4 | Reconnaissance and Vulnerability Scanning | Completed |
| 5 | Authentication and Web Attack Simulation | Completed |
| 6 | Local AI and Safe Payload Variation | Completed |
| 7 | Custom Decoder, Rules, and Logtest | Not Started |
| 8 | CLI Automation and Evidence | Not Started |
| 9 | Preprocessing, Labeling, and Validation | Not Started |
| 10 | End-to-End AI SOC Dataset Project | Not Started |

Progress is updated based on implemented artifacts and validation results, rather than planned activities alone.

---

## 10. Main Reference

Onno W. Purbo (2026).

**AI SOC Mastery: Menyiapkan Script Pentest untuk Membuat Dataset Training AI di WAZUH.**

The book is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).

This repository follows the book's chapter organization and adapts its laboratory exercises into a reproducible project implementation.

---

## Project Philosophy

An AI SOC does not begin with a large model.

It begins with correct data, a controlled laboratory, reliable ground truth, clear evidence, reproducible experiments, and responsible security practices.
