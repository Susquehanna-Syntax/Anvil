# Lane B fixture

A repository Lane B scans in tests and in CI's Lane B end-to-end job. Every file is planted; nothing here
is compiled or run. What each file is for:

| File | Expected |
|---|---|
| `src/app.py` | an `eval` of input (GitLab's Python rules) and a `shell=True` subprocess (bandit B602) |
| `src/suppressed.py` | the same `eval`, carrying `# nosec` and `# nosemgrep`: still reported, because a scanned repository does not get to switch Lane B off |
| `src/main.go`, `go.mod` | a command built from input (gosec G204) |
| `src/copy.c` | a fixed stack buffer filled from input (0xdea's C rules) |
| `src/Digest.java` | MD5 (GitLab's Java rules) |
| `web/app.js` | a `require` of a variable (GitLab's JavaScript rules) |
| `src/clean.py` | nothing |
| `tests/test_planted.py` | an `eval` in a test tree: excluded by the selection's paths |
| `.semgrepignore`, `.bandit` | each tries to hide `src/`; neither may have any effect |
| `api/openapi.yaml` | harvested onto the SAST run for the dynamic tier |
