# Chapter 7 - Custom Rule Scope Validation

## 1. Objective

Verify that AI SOC custom rules only process
events marked with safety_status lab_only.

## 2. Positive Testing

Six laboratory samples were tested using wazuh-logtest.

| Scenario | Expected Rule | Result |
|---|---|---|
| recon_nmap_light | 110010 | PASS |
| auth_ssh_login_failure | 110020 | PASS |
| web_input_attack_pattern | 110030 | PASS |
| fim_file_change | 110040 | PASS |
| suspicious_command_simulation | 110050 | PASS |
| baseline_web_access | 110090 | PASS |

## 3. Negative Testing

Two negative samples were tested.

- Normal SSH authentication failure:
  Only the default Wazuh rule matched.
- Custom event with safety_status not_lab:
  No AI SOC custom rule matched.

## 4. Scope Validation

The parent rule 110000 uses:

safety_status = lab_only

Child rules inherit this condition through if_sid.

Result: PASS for the tested positive and negative samples.

## 5. Conclusion

The custom decoder and rules successfully process
the six laboratory scenarios.

The negative tests also confirm that the tested
non-laboratory events do not trigger AI SOC custom rules.

Further false-positive and false-negative evaluation
is still required.

## 6. Archives

The Wazuh Manager configuration currently has:

- logall: no
- logall_json: no

Therefore, archives.json is not available.
