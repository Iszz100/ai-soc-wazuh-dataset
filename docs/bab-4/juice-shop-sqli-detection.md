# Juice Shop SQL Injection Detection with Wazuh

## 1. Overview

This implementation integrates OWASP Juice Shop application
logs with Wazuh to detect suspicious SQL-related application
errors that may indicate SQL Injection attempts.

The detection is performed using a custom Wazuh rule.

## 2. Log Source

Application:
OWASP Juice Shop

Log source:
Docker JSON log

Log file:
 /var/lib/docker/containers/<container-id>/<container-id>-json.log

Example application event:

Error: SQLITE_ERROR: near "dummy": syntax error

## 3. Custom Wazuh Detection Rule

Rule ID: 111154
Rule Level: 10
Detection Category: SQL Injection
MITRE ATT&CK: T1190
Technique: Exploit Public-Facing Application

The rule uses the JSON decoder and examines the
"log" field using a PCRE2 regular expression.

Detection pattern:

(?i)SQLITE_ERROR.*near.*dummy.*syntax error

## 4. Testing and Validation

The following validation stages were completed:

1. Created the custom Wazuh rule.
2. Validated XML syntax successfully.
3. Tested the rule using wazuh-logtest.
4. Confirmed that rule 111154 matched the test event.
5. Validated Wazuh analysisd configuration.
6. Restarted Wazuh Manager successfully.
7. Verified that the custom rule remained active.
8. Tested end-to-end log collection through the
   Juice Shop Docker JSON log.
9. Confirmed generated alerts in alerts.json.

## 5. Detection Evidence

The Wazuh alert records confirmed:

- Rule ID: 111154
- Severity: 10
- Agent ID: 022
- Agent Name: luis_ubuntuSOCAI
- MITRE ID: T1190
- Detection Group: juice_shop, web_attack, sqli

Two matching alerts were observed.

One event contained the synthetic marker
WAZUH-E2E-111154 and verified end-to-end ingestion.

Another matching application log event was observed
without the synthetic marker.

## 6. Technical Analysis

The SQLite error indicates that the application
encountered an SQL syntax error near the string "dummy".

Such errors can occur when malformed input reaches
a database query.

This behavior can be an indicator of SQL Injection
testing or exploitation attempts.

However, an SQL syntax error alone does not prove
successful SQL Injection exploitation.

The custom rule therefore classifies the event as
a possible SQL Injection indicator.

## 7. Conclusion

The integration successfully demonstrated that
Wazuh can collect Juice Shop Docker application logs,
analyze JSON-formatted events, and generate alerts
using a custom detection rule.

The implementation provides an additional application
layer detection capability alongside existing
host-based monitoring.
