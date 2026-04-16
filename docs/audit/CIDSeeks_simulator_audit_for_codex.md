# CIDSeeks simulator audit and Codex patch plan

## 1. Executive verdict

The uploaded repo is **not** a full attacker-side metadata evaluation harness.
It is best classified as a **SimPy-based discrete-event protocol simulator for end-to-end CIDS workflow evaluation**, with a **thin heuristic PMFA leakage proxy** layered on top.

This means:
- It is **useful** for Evaluation-2 style claims: trust-gated dissemination, topology sensitivity, asynchronous delays, authentication/no-auth sensitivity, message-count overhead, and attack-behavior stress testing.
- It is **not yet sufficient** for the new paper claims around **A-PMFA**, **shadow attackers**, **closed/open-world leakage**, **traffic drift**, **dissemination-budget trade-offs**, **FIBD**, or **DMPO-X**.

## 2. Category classification

### Exact category of the current simulator

**Primary category**
- **Evaluation-2 / discrete-event, protocol-level simulator**
- Above transport stack
- Message/event-level abstraction
- Defender-side / trust-side dominant

**Secondary category**
- **Hybrid simulator**: SimPy asynchronous shell + round-synchronous trust core

### What it is NOT
- Not **Evaluation-1** (clean round-based trust-only validator)
- Not **Evaluation-3** (real attacker-side metadata classifier benchmark)
- Not **packet-level / PCAP / Mininet / transport-stack testbed**
- Not **formal privacy evaluation**

### Best one-line label for the paper

> The current repo is a **SimPy end-to-end protocol simulator with heuristic PMFA proxy metrics**, not yet a full attacker-side metadata leakage evaluation platform.

## 3. Why I classify it this way

### 3.1 It is clearly a SimPy end-to-end protocol simulator
- The repo README and docs position it as a **SimPy-based engine** for CIDSeeks end-to-end protocol evaluation.
- `src/simulation/core/simulation_engine.py` drives the simulation through a SimPy environment and `_simulation_loop(...)`.
- `docs/04_EXPERIMENTS.md` and `docs/02_SYSTEM_SPEC.md` explicitly frame this repo as **Evaluation-2**.

### 3.2 But the trust core is still round-synchronous
- In `src/simulation/core/node.py`, `run_iteration_logic(...)` evaluates trust for **all neighbors each round**, regardless of whether a real dissemination event just happened.
- In `src/simulation/modules/trust/manager.py`, REQUEST vs CHALLENGE is generated **internally** inside `_evaluate_three_level_challenge(...)`, not as a true wire-equivalent message sequence.

### 3.3 PMFA is modeled as selective-behavior logic, not as a trained shadow attacker
- `src/simulation/modules/attacks/behavior_policy.py` uses a **rule/probability-based PMFA classifier** with knobs such as `pmfa_detect_prob`, `pmfa_match_window_rounds`, and `pmfa_min_matches`.
- This is still useful for stress testing trust robustness.
- But it is not a real metadata-learning attacker in the sense required by the revised paper.

### 3.4 The leakage evaluator is currently only a weak proxy
- `src/evaluation/pipeline/run_evaluator.py::_compute_pmfa_stats(...)` trains a **logistic regression** on `delay_ms` and `payload_size` only.
- It fits and evaluates on the **same subset**.
- There is no train/validation/test split, no open-world setting, no temporal model, no drift handling.

## 4. Deep code diagnosis

## 4.1 Strengths of the current repo

### A. Architecture is already structured enough to evolve
Good news:
- attack behavior is separated into `behavior_policy.py`
- trust is separated into `trust/manager.py` and `trust/calculator.py`
- privacy has its own `privacy/module.py`
- collaboration has its own `collaboration/module.py`
- evaluation pipeline exists and writes summaries/artifacts

This is a solid foundation for Codex-based refactoring.

### B. Reproducibility discipline is better than typical raw prototypes
The repo already has:
- config-driven runs
- suites and seeds
- DB/event logging
- run-level summaries
- aggregate outputs

This is an asset. Keep it.

### C. It already supports useful paper-side metrics
The current code can support:
- AUROC/AUPRC over trust scores
- false positive / false negative rates
- time-to-threshold / time-to-isolate style summaries
- overhead from logged message events
- topology sweeps
- auth sensitivity sweeps

So it is not a toy. It is simply **misaligned with the new paper claims**.

## 4.2 Core structural mismatches vs the new paper

### A. DMPO is still old DMPO, not DMPO-X

#### Evidence in code
`src/simulation/modules/privacy/module.py`
- uses one `_salt` from config
- computes deterministic prefix-preserving obfuscation from that salt
- emits `alarm_family_id`, `variation_sequence_number`, and `variant_id_hash`
- hard-clamps `variants_per_alarm` into `1..4`
- uses only a few static templates

#### Why this is a problem
The revised paper now expects:
- recipient-scoped aliasing
- epoch-scoped aliasing
- hidden families
- stealth header
- adaptive shaping
- optional cover traffic

The current code instead still behaves like:
- globally stable aliasing
- visible family artifacts
- static variant grammar
- static randomized delay

That is old-DMPO behavior.

### B. Trust engine is still the old three-tier model

#### Evidence in code
`src/simulation/modules/trust/calculator.py`
- advanced tier = `prev + reputation + contribution - penalty`
- final tier = `prev + auth + biometric`
- no FIBD
- no SplitFail
- no CoalCorr

`src/simulation/core/node.py`
- biometric score still comes from generic anomaly/pattern/stability over response history

#### Why this is a problem
The revised paper centers its new trust novelty on:
- **FIBD**
- **split-verifier failures**
- **coalition-aware correlation**

None of those are implemented.

### C. REQUEST/CHALLENGE are internal trust observations, not dissemination-grounded wire events

#### Evidence in code
`src/simulation/modules/trust/manager.py::_evaluate_three_level_challenge(...)`
- selects `msg_kind`
- constructs `alarm_set_id`
- constructs request PMFA surface
- calls `target_node.behavior_policy.respond(...)`
- logs a privacy event with synthetic metadata

This happens during trust evaluation itself.

#### Why this is a problem
It means the attacker is not learning from actual emitted trace sequences. It is learning from a **logical abstraction of evaluation messages**.

That is acceptable for a trust-side simulator.
It is not sufficient for a paper section that claims attacker-side metadata leakage evaluation.

### D. Collaboration fan-out is not really policy-controlled dissemination

#### Evidence in code
`src/simulation/modules/collaboration/module.py`
- `num_targets = min(num_variations, len(valid_neighbors))`
- one variation goes to one selected target
- the `GossipProtocol` object is instantiated, but the actual send path does not use `select_targets(...)` or `process_message(...)`

#### Why this matters
Your paper now wants fan-out `f_t` to be a **policy variable**.
Current behavior couples fan-out to variant count.
That is too rigid and not faithful to DMPO-X.

### E. PMFA attacker is still heuristic, not shadow-attacker grade

#### Evidence in code
`src/simulation/modules/attacks/behavior_policy.py`
- `_pmfa_classify(...)` uses:
  - `pmfa_detect_prob`
  - collusion match cache
  - fallback mode
  - DMPO penalty scaling
- no training on trace datasets
- no temporal learning
- no adaptive online retraining
- no traffic-drift module

#### Why this matters
The revised paper’s A-PMFA needs an attacker that learns from metadata features over time.
The current PMFA attacker is **parameterized selective behavior**, not **trace-trained classification**.

### F. Current leakage evaluation is not statistically valid enough

#### Evidence in code
`src/evaluation/pipeline/run_evaluator.py::_compute_pmfa_stats(...)`
- uses only `delay_ms` and `payload_size`
- fits logistic regression on the same data it evaluates
- uses `dmpo_enabled` subsets named `no_verification` and `with_verification`

`src/evaluation/metrics/enhanced_metrics.py`
- helper functions for leakage datasets exist
- but they are still heuristic and are not integrated into a real attacker evaluation pipeline

#### Why this matters
This causes four issues:
1. **train=test leakage** → optimistic numbers
2. **feature poverty** → misses burst/fan-out/path/alias reuse/sequence dynamics
3. **terminology mismatch** → `dmpo_enabled` is not “verification”
4. **dataset split ambiguity** → challenge and normal traces may not coexist correctly inside each subset

### G. PMFA metric labeling is semantically wrong

#### Evidence in code
In `_compute_pmfa_stats(...)`, subsets are labeled:
- `no_verification`
- `with_verification`

but the split variable is actually:
- `dmpo_enabled`

This is a semantic bug.

### H. ChallengeManager is basically orphaned relative to canonical flow

#### Evidence in code
- `trust/challenge_manager.py` exists
- `three_level_challenge.py` refers to `node.challenge_manager`
- but `Node` does not initialize a `challenge_manager`
- the canonical trust flow is handled directly by `TrustManager`

#### Why this matters
This increases confusion and makes future Codex modifications riskier.

### I. Some helper functions exist but are currently orphaned

#### Evidence in code
`src/evaluation/metrics/enhanced_metrics.py`
- `compute_privacy_leakage_auc(...)`
- `build_pmfa_leakage_datasets(...)`

These exist, but the current run-level PMFA evaluation path does not use them as a proper end-to-end experimental protocol.

## 4.3 Specific implementation flaws that matter for publication quality

### 1. Variant diversity is weaker than it looks
In `privacy/module.py`, the first two templates are effectively identical.
So “3 variants” does not actually mean 3 semantically distinct observation families.

### 2. Global salt creates stable aliasing
The current privacy module uses one salt from `feature_config['privacy_salt']`.
This is global-stability behavior, not per-recipient/per-epoch aliasing.

### 3. Visible family identifiers remain easy to correlate
`alarm_family_id`, `variation_sequence_number`, and `variant_id_hash` are present in the alarm objects.
That is the opposite of a stealth-header design.

### 4. Trust update cadence is too synthetic
Every node evaluates all neighbors every round.
This inflates the observation process and weakens the interpretation of time-to-quarantine as a dissemination-grounded metric.

### 5. No packetization / no PCAP / no emission sequence export
The repo exports message events and DB events, but not packet-level traces or PCAP-like emissions.
That means the attacker is not evaluating the same observation surface a realistic metadata learner would see.

### 6. No open-world, no drift, no temporal sequence models
There is no implementation of:
- open-world leakage evaluation
- train/test drift split
- temporal classifier
- online attacker adaptation

## 5. Bottom-line mapping to the new paper claims

## Claim-by-claim status

### Claim: trust-side robustness under Sybil / Collusion / Betrayal / PMFA
**Status:** partially supported
- yes for classical PMFA-style selective behavior
- no for the newer A-PMFA formulation in the revised paper

### Claim: attacker-side metadata leakage reduction
**Status:** weakly and insufficiently supported
- current code only has a heuristic proxy
- not enough for the new draft

### Claim: open-world / traffic-drift attacker evaluation
**Status:** not supported

### Claim: DMPO-X dissemination-budget trade-off
**Status:** not supported
- current code can measure messages/bytes/latency
- but there is no real policy controller, no matched-budget evaluation, and no modern attacker loop

### Claim: FIBD / split-verifier / coalition-aware attribution
**Status:** not supported

### Claim: mini-testbed / PCAP evidence
**Status:** not supported

## 6. Practical answer to “simulator ini masuk kategori mana?”

Use this wording in your own notes:

> This simulator belongs to the **Evaluation-2 class**: a **SimPy discrete-event end-to-end protocol simulator** for trust, dissemination, authentication, and attack-behavior dynamics. It is **not yet** an attacker-side metadata evaluation framework, and it should therefore be treated as **defender-side evidence with only a lightweight PMFA leakage proxy**.

## 7. What Codex should change — priority order

## Priority 0 — freeze the truth in the repo/docs

### Goal
Prevent overclaim.

### Tasks
1. Update README and docs to say explicitly:
   - this repo is **Evaluation-2**
   - attacker-side leakage support is currently **proxy-level only**
2. Remove any wording implying:
   - open-world already exists
n   - drift already exists
   - shadow attacker already exists

### Acceptance criteria
- README, docs/02, docs/04, and UI labels no longer imply full attacker-side evaluation.

## Priority 1 — make the current simulator internally honest and publishable as Evaluation-2

### Goal
Turn this into a clean, defensible protocol simulator.

### Tasks
1. **Refactor trust updates to be event-derived**
   - Stop evaluating every neighbor blindly each round.
   - Only create trust observations when there is an actual dissemination or challenge interaction.

2. **Use actual collaboration fan-out logic**
   - Route target selection through `GossipProtocol` or a new dissemination policy object.
   - Decouple `fanout` from `variants_per_alarm`.

3. **Clean dead/orphan paths**
   - remove or fully integrate `ChallengeManager`
   - remove or clearly mark unused helper methods

4. **Fix PMFA metric naming**
   - rename `no_verification/with_verification` into `no_dmpo/with_dmpo` if that is what the code really means

5. **Fix data leakage in evaluator**
   - split train/validation/test by seed or round
   - never fit and score on the same exact data

### Acceptance criteria
- trust updates correspond to actual interactions
- PMFA metric names are semantically correct
- evaluator uses train/test separation

## Priority 2 — lift DMPO to DMPO-X-lite inside this repo

### Goal
Bring the simulator closer to the revised paper without yet building a full packet testbed.

### Tasks
1. **Replace global salt with recipient-epoch scoped aliasing**
   - file: `src/simulation/modules/privacy/module.py`
   - implement `alias(sender, recipient, epoch, entity)`

2. **Hide family metadata from visible alarm objects**
   - remove visible `alarm_family_id`, `variation_sequence_number`, `variant_id_hash` from attacker-visible payload
   - store them in an internal `stealth_meta` field or separate sender/receiver-private structure

3. **Replace static template list with hidden-family generator**
   - families should be semantically equivalent but observationally diversified
   - do not hard-limit to 4 hardcoded templates

4. **Add policy-controlled shaping knobs**
   - `K_t` family count
   - `f_t` fan-out
   - `l_t` length bucket
   - `d_t` delay law
   - `r_t` cover rate

5. **Add optional cover emissions**
   - cover traces must be logged separately so attacker traces can include them

### Acceptance criteria
- no globally visible family ids in attacker-visible payloads
- fan-out and variant count are independent parameters
- cover traffic exists as a first-class emission type

## Priority 3 — add real attacker-side metadata evaluation inside the repo

### Goal
Create a genuine Evaluation-3 layer from the traces produced by this repo.

### Tasks
1. **Export trace datasets explicitly**
   - one row/event per emission
   - include sequence grouping keys
   - include sender/receiver view, round, delay, bucket size, fan-out, path/hops, alias reuse markers, direction, and cover flag
   - keep a separate label file for verifier-bearing vs ordinary

2. **Create `src/evaluation/attackers/`** with:
   - `shadow_xgb.py`
   - `shadow_logreg.py`
   - `shadow_temporal.py` (TCN/LSTM/1D CNN placeholder if you want)
   - `datasets.py`
   - `splits.py`

3. **Implement proper experiment splits**
   - closed-world split
   - open-world split
   - drift split (train on earlier window, test on later window / changed policy / changed topology)

4. **Metrics**
   - AUROC
   - AUPRC
   - open-world precision / recall
   - attacker advantage
   - calibration if you want stronger analysis

5. **Budget matching**
   - compare configurations under bounded bytes / latency budget
   - do not allow “privacy wins” only because one method sends much more traffic

### Acceptance criteria
- attacker training code exists separately from trust logic
- traces are exported once and consumed by attacker evaluators
- train/test leakage is impossible by construction
- open-world and drift settings are reproducible from config

## Priority 4 — implement the new trust attribution layer

### Goal
Align trust computation with the revised paper.

### Tasks
1. **Add FIBD recorder**
   - maintain behavior sketches conditioned on hidden family and context
   - response tuple should include at least correctness, latency bucket, forwarding decision

2. **Add SplitFail**
   - verifier shares distributed across messages or rounds
   - compute reconstruction success/failure per peer

3. **Add CoalCorr**
   - residual coordination across suspicious peers after conditioning on context

4. **Refactor advanced and final trust tiers**
   - replace old generic `penalty` and `biometric` dominance with attribution-aware components

### Acceptance criteria
- trust state contains explicit FIBD / SplitFail / CoalCorr terms
- ablations can disable each term independently

## Priority 5 — add paper-ready ablation suites

### Goal
Make evaluation tables reviewer-proof.

### Required ablations
1. Full CIDSeeks
2. NoTrustGate
3. NoPrivacyGuard
4. NoAuth
5. FlatTrust
6. NoFIBD
7. NoSplitVerifier
8. StableAliasOnly
9. NoCover

### Acceptance criteria
- each ablation is selectable via config
- summary tables export all ablation results in one unified format

## Priority 6 — mini-testbed / trace realism bridge

### Goal
Add one practical layer beyond simulation.

### Minimal path
1. Build a local sender/receiver harness
2. Serialize shaped messages over localhost sockets
3. Capture timestamped send/receive events
4. Export PCAP-like or packet-event traces
5. Re-run the shadow attacker on those traces

### Acceptance criteria
- at least one small practical trace dataset exists outside pure simulator logs
- shadow attacker can run on both simulated traces and practical traces

## 8. Concrete file-by-file Codex patch map

## `src/simulation/core/node.py`
### Change
- Stop unconditional `for neighbor in self.neighbors: evaluate(neighbor)` per round.
- Introduce event-driven trust update queue.

### Why
Current logic over-synthesizes observations.

## `src/simulation/modules/privacy/module.py`
### Change
- replace global `_salt` design with `recipient_id`, `epoch`, and `context`
- remove visible family metadata from payload
- generalize family rendering beyond 4 static templates
- add cover emission generator

### Why
Current module is static old DMPO, not DMPO-X.

## `src/simulation/modules/collaboration/module.py`
### Change
- decouple `num_targets` from `num_variations`
- use policy-driven `(K_t, f_t, d_t, r_t)`
- optionally schedule cover emissions
- route actual target selection through a dissemination policy class

### Why
Current dissemination logic is not faithful to the new paper.

## `src/simulation/modules/trust/manager.py`
### Change
- replace internal REQUEST/CHALLENGE-only abstraction with trace-linked observation objects
- implement FIBD / SplitFail / CoalCorr
- keep challenge tiering, but make it evidential rather than generic

### Why
Current trust engine is still old-CIDSeeks.

## `src/simulation/modules/attacks/behavior_policy.py`
### Change
- keep existing PMFA as `pmfa_heuristic`
- add new attacker mode `apmfa_shadow`
- attacker should ingest trace-derived feature vectors or posterior estimates
- support drift-aware adaptation hooks

### Why
Needed to separate classical PMFA stress testing from revised-paper A-PMFA.

## `src/evaluation/pipeline/run_evaluator.py`
### Change
- remove train==test PMFA evaluator
- use trace export + attacker modules
- rename metrics semantically correctly
- support closed-world / open-world / drift result tables

### Why
Current PMFA stats are too weak and partially mislabeled.

## `src/evaluation/metrics/enhanced_metrics.py`
### Change
- move leakage helpers into dedicated attacker-eval pipeline or integrate them properly
- expand feature extraction beyond delay/payload/variant-present
- add matched-budget reporting utilities

### Why
Current helper logic is underpowered and partially orphaned.

## `configs/experiments/`
### Add or revise
- `experiments_eval1_trust_core.yaml`
- `experiments_eval2_protocol.yaml`
- `experiments_eval3_shadow_attacker.yaml`
- `experiments_eval4_testbed_bridge.yaml`
- ablation suite configs

### Why
Your paper now has multiple evaluation layers. Config structure should reflect that explicitly.

## 9. Suggested new repo taxonomy

Use this model going forward:

### Evaluation-1 — trust core validation
- round-based
- no topology needed
- fast sweeps
- validates convergence, AUROC, false quarantine, time-to-quarantine

### Evaluation-2 — SimPy end-to-end protocol simulator
- current repo’s main role
- async dissemination, topology, auth, trust gating, overhead

### Evaluation-3 — attacker-side metadata evaluation
- trace export from Eval-2
- XGBoost / temporal attacker
- closed/open-world/drift
- matched-budget comparisons

### Evaluation-4 — mini-testbed realism layer
- localhost or Mininet-like trace generation
- packet or packet-like emissions
- PCAP/trace evidence

## 10. Minimal publishable strategy if you do not want a full rewrite now

If you want the fastest realistic route:

### Keep this repo as Evaluation-2 only
Do this now:
1. fix trust/event alignment
2. fix PMFA metric naming
3. clean dissemination logic
4. clean docs so the repo no longer overclaims

### Then create a separate attacker-eval package
Create a smaller companion repo or submodule:
- consume exported traces from this repo
- run shadow attacker experiments there
- produce Section 5.2 tables/figures there

This is the least risky route.

## 11. Short final recommendation

Do **not** force this current repo to pretend it already closes the full evaluation loop.
The honest and strong framing is:

> The current codebase is already a good **Evaluation-2 SimPy protocol simulator**. Use it for end-to-end trust/dissemination/authentication dynamics. Then either (a) upgrade it with a real shadow-attacker layer and DMPO-X-lite, or (b) keep it as Evaluation-2 and add a separate attacker-side evaluation stack for Section 5.2.

That framing is both accurate and publishable.
