# Documentation Index

| Doc | Topic | Evidence class |
|---|---|---|
| [project-overview.md](project-overview.md) | Purpose, architecture map, entry points | repo-verified |
| [historical-source-analysis.md](historical-source-analysis.md) | Snapshots, commits, advisory, fix diff | primary-source (byte-exact files + ledger) |
| [rng-technical-analysis.md](rng-technical-analysis.md) | State size vs seed width vs entropy; model caveats | mixed: proven/inferred labelled |
| [rng-conformance.md](rng-conformance.md) | U2 external-oracle verification & UNVERIFIED list | externally oracled (libstdc++) |
| [entropy-path-analysis.md](entropy-path-analysis.md) | U3 seed→RNG→bytes→mnemonic chain with PROVEN/INFERRED/GAP tags | snapshot code + explicit gaps |
| [evidence-provenance.md](evidence-provenance.md) | Ledger/provenance system and invariants | repo-verified |
| [reproduction-methodology.md](reproduction-methodology.md) | Install, run, integrity checks, oracle regeneration | executed commands |
| [limitations.md](limitations.md) | Deviations from history, open questions L1–L4, safety scope | — |

WASM status: no historical artefact reconstruction performed; rationale in
limitations.md §2. The conformance layer above is the substitute evidence path
until an authentic build can be pinned.
