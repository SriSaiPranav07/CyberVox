# Training, Validation, & Demo Datasets

## Reference Datasets Used

1. **CIC-IDS2017 (Canadian Institute for Cybersecurity)**:
   - License: Open Academic Research License
   - Labels: Benign, DoS/DDoS (SYN, UDP, HTTP), PortScan, Infiltration, Botnet.
   - Usage: Statistical baselines for packet size dispersion and port entropy.

2. **CTU-13 Botnet Dataset (Czech Technical University)**:
   - License: Creative Commons Attribution 4.0 International
   - Labels: Real botnet C2 traffic captures (Neris, Rbot, Virut, Donbot, Murlo).
   - Usage: Inter-arrival time (IAT) periodicity baselines and JA3 signatures.

3. **360 Netlab DGA Dataset**:
   - License: Open Threat Intelligence Research
   - Labels: Domain generation algorithms (Cryptolocker, Banjori, Necurs, Mirai, Matsnu).
   - Usage: Shannon entropy and n-gram perplexity thresholds.

## Training vs. Evaluation vs. Demo Replay Separation
- **Training Set (60%)**: Used for Random Forest classification and Isolation Forest fitting.
- **Validation/Test Set (20%)**: Used for hyperparameter tuning and class-wise precision/recall evaluation.
- **Demo Replay Stream (20%)**: Dedicated, disjoint traffic streams used during live demonstration.
