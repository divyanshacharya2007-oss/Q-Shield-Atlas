# Q-Shield Atlas

Q-Shield Atlas is a PQC-01 migration-planning demonstrator. It inventories RSA/ECC use, compares migration schedules, exercises a deliberately weak toy-RSA capture, gates simulated hybrid migrations, records evidence in a signed Merkle log, and produces an Exposure Tower visualization.

## Architecture

- `data_ingest/` loads the SSL scan sample or a deterministic offline sample and converts records into Atlas assets.
- `detect/` scans repository source/configuration/certificate files with file-and-line evidence and can inspect a live TLS handshake. The demo probes a temporary loopback TLS service only.
- `schedule/` formulates a weekly capacity-constrained MILP and compares its result with FCFS and highest-risk-first baselines.
- `capture/` creates a synthetic TLS-like handshake and ciphertext using a labeled 64–128-bit RSA key. `attack/` factors only toy-size moduli, writes decryption evidence, and supports offline replay inspection.
- `gates/` checks synthetic TLS 1.3 hybrid ML-KEM/ML-DSA service state, applies transactional migration waves, and requires legacy replay to fail explicitly after migration.
- `ledger/` records SHA-256 chained entries and Merkle roots, run-manifest hashes, and signatures. ML-DSA is used when a supported backend is installed; otherwise classical ECDSA/RSA signing is explicitly labeled as fallback.
- `qaoa/` runs a weekly QUBO cross-check at depths $p=1,2,3$, using a QCloud simulator when configured or the local simulator otherwise. Its output is labeled “Measured cross-check only, no claim of quantum advantage.”
- `viz/` exports the pipeline into `contracts/results.json` and displays the data in a Three.js Exposure Tower with a 2D canvas fallback.

## Assumptions And Limits

- Python 3.12 is the pinned/documented runtime. The launcher accepts Python 3.12 or newer; the current local workspace may use a newer interpreter.
- The included scan fixture and loopback TLS endpoint are demonstration inputs, not a production asset inventory. External live endpoints are never contacted by the demo.
- QpiAI Opt local execution needs its configured Opt credentials and online verification. Without them, the demo solves the same exported MILP matrix with SciPy/HiGHS and records the actual provider.
- QCloud execution needs a configured `API_KEY` and available simulator. Otherwise QAOA runs locally on a statevector simulator. The cross-check is limited to 16 binary variables including capacity slack, and is not evidence of quantum advantage.
- The RSA attack uses textbook RSA with a generated 64-bit toy modulus. It demonstrates classical factoring mechanics only; it is not a simulation or estimate of breaking RSA-2048, and the factoring implementation refuses moduli outside 64–128 bits.
- The capture and hybrid service states are synthetic. They are not a production TLS stack, deployed PQC handshake, or network replay test.
- The ledger and its root anchor are local files under `contracts/`; signatures are not externally timestamped or anchored. If ML-DSA support is absent, `FALLBACK_CLASSICAL` explicitly identifies the classical signature status.
- `contracts/results.json` marks stages that were not supplied or executed as `NOT_RUN`; a missing result is never represented as a successful stage.

## Run

Create a Python 3.12 virtual environment and install the pinned packages:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, create/activate `.venv` with the Python 3.12 launcher and install the same requirements file. Then run the complete pipeline:

```bash
./run_demo.sh
```

Windows Command Prompt or PowerShell can launch the convenience wrapper:

```powershell
.\run_demo.bat
```

The runner exports `contracts/results.json`, starts a local HTTP server if port 8765 is free, and opens `viz/index.html` in the default browser. If QpiAI cloud credentials are unavailable, it uses the documented local fallbacks.

Run all tests from the project root:

```bash
python -m pytest -q tests
```

## Contracts

- `contracts/capture.schema.json` describes the synthetic toy capture.
- `contracts/ledger-entry.schema.json` defines the six-field ledger entry.
- `contracts/results.schema.json` validates the visualization/export contract.