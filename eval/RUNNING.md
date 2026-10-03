# Running the Phase 5 experiments

Every command runs from `eval/` with the harness venv (`.venv/bin/python`). Each experiment has a
`run` step that does the expensive work and a `report` step that writes `results/<id>.json` and
refuses to write it unless the run covers its whole pre-registered sample and its negative
control passed. `python -m anvil_eval.results record <id>` then copies the number into the
register row. It never touches `decision`: only the owner sets that.

Wall times were measured on this machine (Ryzen 5 9600X, RTX 4070, RTX 4060) on 2026-10-03, with
nothing else running unless noted.

## Setup (once; each step is a download or an install, so the owner approves it)

| What | Command | Size |
|---|---|---|
| llama.cpp b11146 (CUDA 13.4 build plus runtime) | unpack both release tarballs into `~/.local/opt/llama.cpp-b11146`, copy the runtime libraries beside the binaries, and unpack the source tarball into `src/` | 589 MB |
| Conversion venv | `python3 -m venv .venv-convert`, then torch 2.11.0 (CPU), transformers 5.18.0, sentencepiece, protobuf, onnx, onnxruntime and llama.cpp's `gguf-py` | 1.3 GB |
| Candidate models | `python -m anvil_eval.models acquire qwen3.5-2b gemma-4-e2b-it unixcoder-base` | 15.4 GB |
| GGUF conversion | `python -m anvil_eval.models convert qwen3.5-2b gemma-4-e2b-it` | about 3 min, CPU |
| Encoder export | `cd src && ../.venv-convert/bin/python -m anvil_eval.encoder export` | about 1 min, CPU |
| CWE 4.20 catalogue | `curl -o data/cwe/cwec_v4.20.xml.zip https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip` (checked against the pin in `anvil_eval/data/cwe.py`) | 2 MB |
| PrimeVul v0.1 | by hand from the v0.1 Google Drive folder linked in github.com/DLVulDet/PrimeVul; put the six `primevul_*.jsonl` files in `data/primevul/`, then `python -m anvil_eval.data.primevul manifest` | 665 MB |
| Recall federation and sample repositories | `python -m anvil_eval.recall acquire` (corpora go to `~/.cache/anvil-eval/recall`, outside the repository, because gate 3 scans every Go file in the tree) | 250 MB on disk |

## The experiments

| Register row | Command | Device | Wall time | Output |
|---|---|---|---|---|
| advisory-permutation | `python -m anvil_eval.experiments.permutation run --model qwen3.5-2b --device CUDA0` and, in parallel, `... --model gemma-4-e2b-it --device CUDA1`; then `... permutation report` | RTX 4070 and RTX 4060, under 4 GB each | 0.7 s an answer on an idle machine; about 30 min each. CPU load from another job makes it about 10 times slower | `results/runs/advisory-permutation/<model>.jsonl` (resumable), then `results/advisory-permutation.json` |
| code-metrics-baseline | `python -m anvil_eval.experiments.baseline report` (after the permutation report) | CPU | features for the 175,797 training functions take 2.4 min once, then are cached | `results/code-metrics-baseline.json` |
| prefill-sweep | `python -m anvil_eval.experiments.prefill run --model qwen3.5-2b --arms rtx4070 rtx4060 cpu12 tier-s cpu1` (and the same for gemma-4-e2b-it), then `... prefill report` | both GPUs, then the CPU alone; run it with nothing else on the machine | about 10 min per model | `results/runs/prefill-sweep/`, `results/prefill-sweep.json` |
| candidates-per-scan | `python -m anvil_eval.experiments.candidates run`, then `... candidates report` | CPU, all cores | about 15 min | `results/runs/candidates-per-scan/counts.json`, `results/candidates-per-scan.json` |
| encoder-round-trip | `python -m anvil_eval.encoder measure --pairs 5000`, then `... encoder report` (after the prefill report) | CPU, 4 threads | about 8 min | `results/runs/encoder-round-trip/timings.json`, `results/encoder-round-trip.json` |
| patch-quality | `python -m anvil_eval.experiments.patch run --jdk 8u202=<JDK 8 home> --jdk 17=<JDK 17 home>`, then `... patch report` | both GPUs plus system RAM for the coder's experts | not yet run: it needs the coder (a 61 GB download), JDK 8 and 17, Maven and network access for Maven at build time | `results/runs/patch-quality/outcomes.jsonl`, `results/patch-quality.json` |

A trial on a few pairs never writes into `results/`: `permutation run --limit 3 --out <scratch path>`.

## What each report checks before it writes

| Experiment | Negative control (the artifact does not validate unless it passes) |
|---|---|
| advisory-permutation | 50 pairs per framing asked again with their own advisory and the prompt cache off: at most one verdict may change |
| code-metrics-baseline | a pair-blind scorer has P-C exactly 0 and precision exactly 0.5, and the model compared with itself overlaps |
| prefill-sweep | one CPU thread is clearly slower than four (ratio under 0.75), so no GPU leaked into a CPU arm |
| candidates-per-scan | a planted file per language family is each flagged, and a clean file is not |
| encoder-round-trip | the worker refuses other paths and malformed bodies, and scores a duplicated pair identically |
| patch-quality | a real canned fix is `verified_fixed` and a cosmetic one `exploit_still_triggers` on the synthetic C case |
