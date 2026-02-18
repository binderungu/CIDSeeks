# Simulation Modules: Active vs Legacy

Dokumen ini mencegah salah edit file pada repo Evaluasi-2.

## Jalur aktif (dipakai `runner.py` / `simulate.py`)
- `src/simulation/modules/ids/module.py`
- `src/simulation/modules/trust/calculator.py`
- `src/simulation/modules/trust/manager.py`
- `src/simulation/modules/trust/challenge_manager.py`
- `src/simulation/modules/authentication/module.py`
- `src/simulation/modules/privacy/module.py`
- `src/simulation/modules/collaboration/module.py`
- `src/simulation/modules/attacks/behavior_policy.py`

## Legacy (arsip; bukan jalur eksekusi canonical)
- `src/simulation/modules/authentication/{auth_manager.py,core_auth_manager.py}` sudah dihapus; gunakan `AuthenticationModule` dari `authentication/module.py`
- `src/simulation/modules/privacy/privacy_manager.py` sudah dihapus; gunakan `PrivacyModule` dari `privacy/module.py`
- `src/simulation/modules/collaboration/collab_manager.py` sudah dihapus; gunakan `CollaborationModule` dari `collaboration/module.py`
- `src/simulation/modules/attacks/{pmfa.py,collusion.py,sybil.py,betrayal.py,core_attacks.py,attack_coordinator.py}` sudah dihapus
- `src/simulation/modules/database/{database_manager.py,database_module.py}` sudah dihapus; gunakan `NodeDatabase` dari `database/node_database.py`
- `src/simulation/modules/ids/ids_module.py` sudah dihapus; gunakan `IdsModule` dari `ids/module.py`

Kebijakan:
- Perubahan fitur/bugfix baru hanya di jalur aktif.
- Referensi historis legacy ada di riwayat git, bukan pada jalur runtime paper saat ini.

Legacy stack tambahan di luar `modules/` (juga non-canonical):
- `src/simulation/{simulator,scenario,reporting,visualization}/` sudah dihapus total
- `src/simulation/{analysis,export,monitoring}/` sudah dihapus total
- `src/simulation/models/` sudah dihapus total
- `src/simulation/core/{simulation_iteration.py,simulation_status.py}` sudah dihapus total
- `src/simulation/utils/{error_handler,event_manager,helpers,icon_handler,performance_monitor,persistence,simulation_state,visualization_helper,exceptions,logger,theme}.py` sudah dihapus total
- `src/simulation/config/{config_manager.py,experiment_runner.py}` sudah dihapus total
- `src/simulation/legacy/` sudah dihapus total
- `src/evaluation/export/result_exporter.py` adalah lokasi exporter kanonis saat ini
