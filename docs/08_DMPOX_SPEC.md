# DMPO-X Specification

DMPO-X pada repo ini menambahkan:
- strategy switch: `dmpo_legacy` vs `dmpo_x`,
- policy metadata (`K_t`, `f_t`, `ell_t`, `d_t`, `r_t`),
- recipient-scoped dan epoch-scoped aliasing,
- opaque stealth header,
- hidden-equivalent message families tanpa marker family yang terlihat,
- budget-aware policy selection,
- cover emission sederhana.

Framing canonical:
- DMPO-X bertujuan **meminimalkan** probe distinguishability pada level stream.
- DMPO-X bukan klaim anonymity absolut.
- Residual leakage yang masih tersisa diarahkan ke trust attribution layer sebagai evidence `FIBD`, `SplitFail`, dan `CoalCorr`.

Artefak runtime minimal yang harus terlihat pada payload `dmpo_x`:
- `privacy_alias_scope = recipient_epoch`
- `privacy_alias_epoch`
- `privacy_alias_epoch_rounds`
- `privacy_policy_decision` pada render/wire privacy logs bila controller aktif
  - minimum berisi policy terpilih dan cost ringkas (`selected_*`,
    `candidate_count`, `objective`, `budget_penalty`)

Catatan: spesifikasi ini hanya menjelaskan jalur runtime/privacy. Evidence attacker-side untuk PMFA diturunkan terpisah oleh evaluator ke `eval3_pmfa/`, sedangkan evidence attribution runtime dibawa oleh event trust dan `summary.csv`.
