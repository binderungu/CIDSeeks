# CIDSeeks simulator — Codex patch instructions

## Objective
Upgrade the current repository from a **SimPy end-to-end protocol simulator with heuristic PMFA proxy** into a repository that can support the revised CIDSeeks evaluation story:
1. **Evaluation-1**: trust-core validation
2. **Evaluation-2**: SimPy end-to-end protocol evaluation
3. **Evaluation-3**: attacker-side metadata leakage evaluation
4. **Evaluation-4**: optional mini-testbed / PCAP export

This patch plan focuses on making the codebase align with the revised paper claims around **A-PMFA**, **DMPO-X**, **FIBD**, **SplitFail**, **CoalCorr**, **open-world leakage**, **traffic drift**, and **dissemination-budget trade-offs**.

---

## Hard verdict on the current repo
Do **not** present the current repo as a full attacker-side leakage evaluation artifact.

Current repo status:
- good for **Evaluation-2**
- partially useful for trust robustness stress testing
- **not sufficient** for attacker-side metadata leakage claims
- **not sufficient** for DMPO-X claims
- **not sufficient** for FIBD/SplitFail/CoalCorr claims

---

## Priority order

### Priority 0 — do not break current Evaluation-2 runs
Preserve current reproducible SimPy experiments while adding new layers.
Do not delete old DMPO immediately. Move it behind a strategy switch.

### Priority 1 — split evaluation layers cleanly
Create explicit evaluation layers:
- `eval1_trust_core/`
- `eval2_simpy_protocol/`
- `eval3_metadata_attacker/`
- `eval4_minitestbed/` (optional)

At minimum, separate configs, outputs, and metrics for these layers.

### Priority 2 — implement DMPO-X as a new privacy strategy
Do **not** mutate old DMPO in-place without versioning.
Implement:
- `dmpo_legacy`
- `dmpo_x`

### Priority 3 — implement new trust attribution signals
Add:
- `FIBD`
- `SplitFail`
- `CoalCorr`

### Priority 4 — build real attacker-side metadata evaluation
Export trace datasets and train real classifiers with proper train/val/test separation.

### Priority 5 — add drift/open-world/budget ablations
Only after Priority 4 works.

---

## Required architectural changes

## 1. Repository taxonomy

### Add these folders
- `src/eval1_trust_core/`
- `src/eval3_metadata_attacker/`
- `src/eval4_minitestbed/` (optional)
- `configs/eval1/`
- `configs/eval2/`
- `configs/eval3/`
- `results/eval1/`
- `results/eval2/`
- `results/eval3/`

### Add docs
- `docs/06_EVAL1_TRUST_CORE.md`
- `docs/07_EVAL3_METADATA_ATTACKER.md`
- `docs/08_DMPOX_SPEC.md`

### Acceptance criteria
- each evaluation layer has independent run entrypoints
- each layer writes outputs into separate result directories
- paper claims can point to the correct layer

---

## 2. Privacy module refactor: old DMPO -> strategy interface

### Current problem
`src/simulation/modules/privacy/module.py` still implements old DMPO:
- global salt
- visible family artifacts
- static variants
- no recipient/epoch scoping
- no stealth header
- no cover traffic
- no policy controller

### Required change
Introduce a strategy interface:
- `LegacyDMPOPrivacyStrategy`
- `DMPOXPrivacyStrategy`

### New files
- `src/simulation/modules/privacy/strategies/base.py`
- `src/simulation/modules/privacy/strategies/dmpo_legacy.py`
- `src/simulation/modules/privacy/strategies/dmpo_x.py`
- `src/simulation/modules/privacy/policy_controller.py`
- `src/simulation/modules/privacy/stealth_header.py`
- `src/simulation/modules/privacy/aliasing.py`
- `src/simulation/modules/privacy/family_renderer.py`
- `src/simulation/modules/privacy/cover_traffic.py`

### DMPO-X minimum behavior
Implement:
- recipient-scoped aliasing
- epoch-scoped aliasing
- hidden-equivalent message families
- stealth header
- adaptive family count `K_t`
- independent fan-out `f_t`
- length bucketization `ell_t`
- delay law `d_t`
- optional cover rate `r_t`

### Important constraints
- `family-id`, `seq`, `variant-id`, verifier shares must not remain visible wire fields
- fan-out must not be forced equal to variant count
- policy controller must operate under explicit bandwidth/latency budgets

### Acceptance criteria
- config can select `privacy.strategy: dmpo_legacy | dmpo_x`
- emitted event logs contain policy metadata without exposing hidden control fields
- fan-out and family count are independent variables

---

## 3. Add DMPO-X policy controller

### Current problem
Current system is hard-coded around variants and random delay.

### Required change
Implement a controller that chooses:
- `K_t`
- `f_t`
- `ell_t`
- `d_t`
- `r_t`

based on:
- severity bucket
- trust bucket
- node load
- attacker score estimate
- bandwidth budget
- latency budget

### New config block
```yaml
privacy:
  strategy: dmpo_x
  controller:
    enabled: true
    budget_bw: ...
    budget_lat_ms: ...
    candidate_policies:
      - {K_t: 2, f_t: 3, ell_t: small, d_t: exp_low, r_t: 0.0}
      - {K_t: 3, f_t: 4, ell_t: medium, d_t: exp_mid, r_t: 0.2}
      - {K_t: 4, f_t: 5, ell_t: medium, d_t: exp_high, r_t: 0.4}
```

### Initial implementation guidance
Start with a finite policy set and a simple selector:
- score = attacker_risk + lambda_bw * bw_cost + lambda_lat * lat_cost
- choose minimum-score policy

No RL is required at first.

### Acceptance criteria
- logs record selected policy per dissemination event
- budget sweep can be run reproducibly

---

## 4. Collaboration layer refactor

### Current problem
`num_targets = min(num_variations, len(valid_neighbors))`
This couples fan-out to variant count.

### Required change
Refactor dissemination path so that:
- peer sampling uses `f_t`
- family rendering uses `K_t`
- assignment of family to peer is separate from peer selection
- cover emissions are scheduled independently

### Acceptance criteria
- one run can have `K_t != f_t`
- logs report both values separately

---

## 5. Trust engine refactor: add attribution signals

### Current problem
Current trust engine remains generic.
No FIBD, no SplitFail, no CoalCorr.

### Required change
Introduce a new attribution layer in trust:
- `FIBDTracker`
- `SplitVerifierTracker`
- `CoalitionCorrelationTracker`

### New files
- `src/simulation/modules/trust/fibd.py`
- `src/simulation/modules/trust/split_verifier.py`
- `src/simulation/modules/trust/coalcorr.py`

### Required behavior
#### FIBD
Track response tuple `R = (acc, lat_bucket, fwd)` conditioned on:
- peer `j`
- context bin `c`
- hidden family `z`

Compute divergence between family-conditioned response distributions.

#### SplitFail
Track whether verifier reconstruction attributable to a peer fails.

#### CoalCorr
Track suspicious residual coordination after controlling for context.

### Integration target
Update advanced-tier penalty to consume:
- `FIBD`
- `SplitFail`
- `CoalCorr`

### Acceptance criteria
- trust summaries export these three quantities per peer per window
- ablation switches exist for each component

---

## 6. Replace synthetic PMFA-only logic with two attacker layers

### Current problem
`behavior_policy.py` models PMFA as a rule/probability process, not a trained metadata attacker.

### Required change
Keep two layers:

#### Layer A — online malicious behavior policy
Still needed for node behavior inside SimPy.
But rename it clearly:
- `SelectiveInsiderPolicy`
- not `real attacker classifier`

#### Layer B — shadow attacker pipeline
Create a separate offline/sidecar evaluation pipeline that trains on exported traces.

### New files
- `src/eval3_metadata_attacker/dataset_builder.py`
- `src/eval3_metadata_attacker/features.py`
- `src/eval3_metadata_attacker/models.py`
- `src/eval3_metadata_attacker/run_closed_world.py`
- `src/eval3_metadata_attacker/run_open_world.py`
- `src/eval3_metadata_attacker/run_drift.py`

### Acceptance criteria
- paper no longer conflates simulated selective insider behavior with trained leakage attacker

---

## 7. Real metadata trace export

### Current problem
Current PMFA stats rely on tiny feature sets and synthetic event views.

### Required change
Export trace units that correspond to dissemination episodes.
Each trace should include ordered event sequence and summary features.

### Per-trace metadata should include
- sender id
- receiver id
- epoch
- policy id
- `K_t`, `f_t`, `ell_t`, `d_t`, `r_t`
- emitted packet/message count
- inter-arrival sequence
- payload-size sequence
- burst count
- burst size stats
- delay stats
- alias reuse indicators
- family assignment indicators (hidden in protocol, but available to evaluator as ground truth)
- verifier-bearing label
- challenge tier label if relevant
- attack label
- topology context
- round/time window

### Export format
- row-level CSV/Parquet for summary features
- JSONL for sequence traces

### Acceptance criteria
- eval3 can rebuild datasets without reaching into internal simulation objects

---

## 8. Proper attacker-side models

### Minimum model set
Implement at least:
- logistic regression baseline
- XGBoost or LightGBM tree-based model
- one temporal model over sequences
  - TCN, 1D CNN, or lightweight GRU is enough

### Evaluation settings
- closed-world
- open-world
- traffic drift

### Metrics
- ROC-AUC
- PR-AUC
- open-world precision/recall
- attacker advantage
- calibration (optional but useful)

### Required statistical hygiene
- no train=test evaluation
- fixed train/val/test split or cross-validation by seed
- report confidence intervals over multiple seeds

### Acceptance criteria
- each attack experiment writes metrics and plots separately for each model

---

## 9. Drift support

### Current problem
No real drift evaluation exists.

### Required change
Implement drift by perturbing one or more of:
- alarm payload distributions
- fan-out distributions
- delay laws
- alias epochs
- benign workload rate
- topology changes

### Recommended modes
- `none`
- `mild`
- `moderate`
- `severe`

### Acceptance criteria
- attacker models trained on pre-drift data can be evaluated post-drift
- optional adaptive retraining protocol exists

---

## 10. Open-world evaluation

### Required change
Define positive class as verifier-bearing traces and introduce many non-verifier/background traces.

### Acceptance criteria
- paper can report open-world precision/recall at fixed operating points
- false positives are measured against background classes, not only matched binary subsets

---

## 11. Fix evaluation semantics and naming

### Current bug
`_compute_pmfa_stats(...)` uses `dmpo_enabled` subsets but labels them `no_verification` and `with_verification`.

### Required change
Rename outputs to match actual semantics:
- `baseline_no_privacy` / `legacy_dmpo` / `dmpo_x`
- never call `dmpo_enabled` = `verification`

### Acceptance criteria
- all metric names align with paper terminology

---

## 12. Fix trust update timing

### Current problem
Each node evaluates trust for all neighbors every round.
That is convenient, but it weakens event-faithfulness.

### Required change
Move toward event-coupled trust updates:
- immediate updates on actual dissemination/response events
- optional periodic summarization window
- keep round-based batch mode only as explicit ablation or fallback

### Acceptance criteria
- config can choose `trust_update_mode: event | round_batch`
- default for new experiments should be `event`

---

## 13. Add ablation switches explicitly

### Required ablations
Implement config switches for:
- legacy DMPO vs DMPO-X
- no view-scoped aliasing
- no stealth header
- no adaptive shaping
- no cover traffic
- no FIBD
- no SplitFail
- no CoalCorr
- no trust gating
- no auth

### Acceptance criteria
- each ablation is selectable from config
- result exports record exact ablation signature

---

## 14. Add dissemination budget analysis

### Required outputs
Per run report:
- bytes per alert
- messages per alert
- median dissemination latency
- p95 dissemination latency
- cover-message fraction
- fan-out distribution
- policy selection histogram

### Acceptance criteria
- budget plots can be generated without manual recomputation

---

## 15. Optional mini-testbed

### Recommended scope
Do not overbuild initially.
Implement a lightweight localhost or Mininet testbed that:
- serializes shaped emissions
- sends them over real sockets
- captures packet traces
- exports PCAP-derived features

### Why this matters
This gives credibility to attacker-side leakage claims and connects SimPy results to real transport artifacts.

### Acceptance criteria
- at least one reproducible small-scale testbed script exists
- traces can be fed into eval3 dataset builder

---

## File-by-file minimum patch map

### `src/simulation/modules/privacy/module.py`
- extract legacy behavior into `dmpo_legacy.py`
- remove visible family control fields from DMPO-X path
- stop using one global salt for all recipients/epochs in DMPO-X path

### `src/simulation/modules/collaboration/module.py`
- separate family rendering from peer sampling
- add independent fan-out
- integrate cover emissions

### `src/simulation/modules/trust/manager.py`
- add hooks to new attribution trackers
- stop treating synthetic request/challenge metadata as the main leakage evaluation source

### `src/simulation/modules/trust/calculator.py`
- introduce new advanced-tier penalty terms
- add ablation-aware composition

### `src/simulation/modules/attacks/behavior_policy.py`
- rename PMFA logic to selective insider policy semantics
- keep as online node behavior model
- do not claim this file implements shadow attacker evaluation

### `src/evaluation/pipeline/run_evaluator.py`
- deprecate current `_compute_pmfa_stats(...)`
- replace with adapters that call eval3 outputs

### `src/evaluation/metrics/enhanced_metrics.py`
- keep generic metrics only
- move leakage-classifier logic out into eval3 package

---

## Minimal publishable path

If time is limited, do this in two phases.

## Phase A — enough for a strong revised paper draft
1. keep current repo as **Evaluation-2**
2. add explicit wording that current repo is protocol-level SimPy evaluation
3. implement DMPO-X-lite:
   - recipient/epoch aliasing
   - hidden families
   - separate `K_t` and `f_t`
   - optional cover
4. add FIBD-lite and SplitFail-lite
5. export trace datasets
6. build separate eval3 with XGBoost + one temporal model
7. report closed-world, open-world, drift, and budget metrics

## Phase B — enough to look much stronger
1. add CoalCorr
2. add event-coupled trust updates
3. add mini-testbed / PCAP export
4. add stronger shadow attacker and retraining under drift

---

## What Codex should NOT do
- do not claim packet-level realism if still operating at message/event level
- do not report PMFA leakage AUC from train=test logistic regression
- do not keep `dmpo_enabled` mislabeled as `verification`
- do not silently mutate old DMPO into DMPO-X without preserving baseline comparability
- do not mix trust-core evaluation and attacker-side leakage evaluation into one metric block

---

## Final expected outcome
After this patch set, the repository should support the following honest statement:

> The CIDSeeks artifact consists of a SimPy-based end-to-end protocol simulator for defender-side trust and dissemination evaluation, plus a separate attacker-side metadata evaluation pipeline operating on exported dissemination traces. Together, these layers support closed-world, open-world, drift, ablation, and dissemination-budget analyses for CIDSeeks and DMPO-X.
