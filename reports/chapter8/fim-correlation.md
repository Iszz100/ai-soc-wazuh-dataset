# Chapter 8 - FIM Ground Truth Correlation

- Run ID: `run-b8e8c7061c47`
- Ground Truth: 5
- Normalized Wazuh alerts: 5
- Exact matches: 2
- Existing-file overwrite correlations: 2
- Operations without actual state change: 1
- Operations without alert: 0
- Preparation alerts: 1

## Results

| Operation | Wazuh Event | Correlation Status |
|---|---|---|
| create_file | modified | CORRELATED_EXISTING_FILE_OVERWRITE |
| modify_file | modified | MATCH |
| chmod_file | - | NO_STATE_CHANGE |
| create_suspicious_dummy | modified | CORRELATED_EXISTING_FILE_OVERWRITE |
| delete_file | deleted | MATCH |

## Analysis

- Four operations have corresponding Wazuh alert evidence.
- Two creation operations were reported as modifications
  because their target files existed from previous testing.
- The chmod operation did not produce a new alert because
  the target permission was already rw-------.
- One additional ownership-change alert originated from
  preparation before the FIM execution.

## Limitations

Correlation uses exact file paths and a one-second time window.
The chmod operation still requires an independent permission-change
test to validate detection of an actual permission transition.
