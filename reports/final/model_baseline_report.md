# Model Baseline Report

- Dataset: `datasets/final/dataset.parquet`
- Records used: 6

## Label Distribution
- malicious: 5
- benign: 1

## Supervised Models

### logistic_regression

- Status: skipped
- Reason: Skipped: each class needs at least two records for a meaningful stratified split.

### random_forest

- Status: skipped
- Reason: Skipped: each class needs at least two records for a meaningful stratified split.

### hist_gradient_boosting

- Status: skipped
- Reason: Skipped: each class needs at least two records for a meaningful stratified split.

## Isolation Forest
- status: trained_exploratory
- records: 6
- score_min: -0.21866653103170275
- score_max: 0.1447047755157569
- anomaly_count: 2
- normal_count: 4
- note: Anomaly baseline only; small sample and not a production classifier.

## Rule-Based Baseline
- Status: not_evaluable
- Rule: `rule_level >= 7 -> malicious else benign`
- FPR: N/A
- FNR: N/A
- Confusion matrix: `-`

## Critical Notes
- Do not interpret accuracy alone.
- False negatives are important in SOC detection.
- False positives increase analyst workload.
- Compare ML models with rule-based baseline.
- Small datasets demonstrate pipeline execution, not production performance.
- Skipped models are not evidence of successful training.
