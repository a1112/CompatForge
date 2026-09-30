# Retained deployed-service adapters

The checked-out branch starts from CompatForge main. The rolling VM used an additional generation/debugger service baseline held in its build workspace. Both differences are retained here rather than claiming that the main-tree CLI alone produced the deployed binary.

`2026-09-30-generation-service-preparing.patch` adapts the earlier generation service preparation ownership. It passed its isolated checks but is **not** the final VM deployment baseline.

`2026-09-30-stage2-profile-preparing.patch` is the final profile and cancellation delta against `/srv/forge-apps-build/rolling-1000-compatforge-stage2`. Its JSON companion pins every preimage/postimage. It retains generation, debugger configuration, debugger lease and export behavior, with a closing check before debug launch. The final isolated target directory was `/srv/forge-apps-build/targets/compatforge-stage2-peazip-classic`; the deployed CLI SHA-256 is `12c0404f79f2d063e2e5e71d42981ebbecd102b5770d363588f1e7c1a4938f62`.

The fresh target directory matters: a reused target directory initially mixed prior source APIs. A first activation attempt also failed the original-context initializer integrity check; another used an older service lacking debuggerRuntime. Each restored the original service. The final activation used a separate authorized context policy file, preserving the original context and historical runtime bindings.

The final baseline passed domain (16), orchestrator (37), process (111), service (84) and debug (22) tests, followed by release build and actual Wine installation, preparing cancellation/shutdown, GUI workflows, Store update/rollback and restart. No installer or signing key is retained in this directory. Deployment, live test and publication records are in `ForgeStore/docs/evidence/2026-10-01-peazip-*` in the shared project.

Cancellation before installer spawn is guarded by the preparation owner and spawn gate. A failed cleanup retains ownership/quarantine. The early live cancellation measurement of 0.242 seconds is not a general maximum: pre-existing individual font registry commands still run within their own bounded command deadline before the owner can finish cleanup.
