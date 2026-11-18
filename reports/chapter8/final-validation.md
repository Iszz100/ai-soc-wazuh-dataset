# Chapter 8 - Dataset Generation and Wazuh Validation

## 1. Dataset Orchestration

Orchestrator execution:
- Run ID: run-20261118T211033Z-c9c56425
- Benign web access: successful
- Recon simulation: successful
- SSH authentication simulation: successful
- Web input simulation: successful

The automated remote FIM and suspicious command steps initially
failed because the configured SSH private key was unavailable.

Both activities were subsequently executed manually using
interactive SSH password authentication.

## 2. FIM Ground Truth

Successful FIM execution:
- Run ID: run-b8e8c7061c47
- Ground Truth records: 5
- Successful operations: 5

Operations:
1. create_file
2. modify_file
3. chmod_file
4. create_suspicious_dummy
5. delete_file

## 3. Wazuh FIM Validation

Wazuh generated eight alerts for the monitored directory
in the inspected alert snapshot.

Five normalized alerts were selected for the successful
execution correlation, including one preparation alert.

Correlation:
- Exact matches: 2
- Existing-file overwrite correlations: 2
- Operations without actual state change: 1
- Operations without alert: 0
- Preparation alerts: 1

The chmod operation did not create a new permission transition
because the target already had rw------- permissions.

A separate permission-change test remains necessary.

## 4. Suspicious Command Detection

Manual execution:
- Run ID: run-7844f261c438
- Execution status: success
- Wazuh custom rule: 110050
- Rule description: AI SOC dataset suspicious command scenario
- Safety status: lab_only
- Matching custom alerts: 1

The custom rule successfully detected the simulated
suspicious command event.

## 5. Dataset Candidate

The candidate combines:
- Ground Truth records
- Normalized FIM alerts
- Normalized custom Wazuh alerts

The candidate remains local and is not published as raw
correlated Wazuh evidence.

## 6. Automation

The following components were prepared:
- Dataset orchestrator
- Dataset cycle shell runner
- Baseline configuration
- Old run inspection utility
- Dataset candidate builder

The cron schedule is documented but has not been installed.

## 7. Limitations

- SSH remote execution still requires manual authentication
  or a separately configured authentication mechanism.
- Permission-change detection needs an independent test.
- False-positive and false-negative evaluation remains future work.
- Wazuh API and Indexer were not reachable from the attacker host;
  alert export was performed directly on the Manager container.

## 8. Conclusion

Chapter 8 successfully demonstrates controlled dataset generation,
Ground Truth collection, Wazuh FIM monitoring, custom alert
detection, and correlation between laboratory activities
and security monitoring evidence.
