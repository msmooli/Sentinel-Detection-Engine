An Enterprise Detection-as-Code (DaC) Framework for Microsoft Sentinel

##   Summary
*This repository implements an Enterprise Detection-as-Code (DaC) framework designed to orchestrate the end-to-end lifecycle of security telemetry within Microsoft Sentinel. By replacing manual portal configurations with a GitOps pipeline, this ensures that defensive logic remains auditable, scalable, and resilient against unauthorized changes.* 

##  Architectural Overview
The framework is built on the principle of **Continuous Integration/Continuous Deployment (CI/CD)** for security operations:
* **Logic:** Standardized KQL queries wrapped in ARM/JSON templates for native Azure deployment.
* **Validation:** Integrated Red-Team simulation scripts to perform unit testing on every detection.
* **Governance:** GitHub provides a full version history of all defensive logic.

##  Technical Stack
* **SIEM/SOAR:** Microsoft Sentinel
* **Query Language:** Kusto Query Language (KQL)
* **Automation:** GitHub Actions / Sentinel Repositories
* **Schema:** Azure Resource Manager (ARM)
* **Testing:** PowerShell

##  Repository Structure
| Directory | Purpose |
| :--- | :--- |
| `/Detections` | Production-ready Sentinel Analytics Rules mapped to MITRE ATT&CK. |
| `/Validation` | Attack simulation scripts used to verify telemetry ingestion and alerting. |

##  Featured Detections (MITRE Mapping)
| Rule Name | Technique ID | Tactic | Severity |
| :--- | :--- | :--- | :--- |
| **RDP Hijacking** | T1563.002 | Lateral Movement | Medium |
| **New Service Creation** | T1543.003 | Persistence | High |
| **Brute Force Success** | T1110 | Credential Access | Critical |

##  Deployment & Testing
1. **Sync:** Link this repository to a Sentinel workspace via the **Content Management** integration.
2. **Automate:** GitHub Actions will automatically deploy committed JSON templates to the SIEM.
3. **Verify:** Execute `./Validation/simulate_attack.ps1` on a target endpoint to trigger alerts and validate the detection pipeline.

---
