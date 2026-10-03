"""The permutation experiment end to end against fake models whose answers are known.

A model that reads the advisory must land in the pass band; one that ignores it must land in the
fail band. Both are run through the real plan, the real answer parsing, the real report and the
real bootstrap, so the only thing replaced is the model.
"""

from __future__ import annotations

import json
import math

import pytest

from anvil_eval import adjudicator
from anvil_eval.data import cwe, primevul
from anvil_eval.experiments import permutation as perm

CWES = ["CWE-121", "CWE-416", "CWE-190", "CWE-476", "CWE-787", "CWE-20"]
CATALOGUE = {c: cwe.Entry(c, f"name of {c}", f"description of {c}") for c in CWES}


def _pairs(n: int) -> list[primevul.Pair]:
    out = []
    for i in range(n):
        label = CWES[i % len(CWES)] if i % 10 else "NVD-CWE-Other"
        v = primevul.Function(str(i), "proj", f"c{i}", 1, f"int f{i}(int a) {{ bad{i}(); }}",
                              (label,), f"CVE-2020-{i}", "" if i % 7 == 3 else f"text {i}")
        f = primevul.Function(str(i), "proj", f"c{i}", 0, f"int f{i}(int a) {{ good{i}(); }}",
                              (label,), f"CVE-2020-{i}", v.cve_desc)
        out.append(primevul.Pair(f"proj@c{i}:f{i}", v, f))
    return out


class FakeModel:
    """Answers through the same wire format llama-server uses, from a rule over the prompt."""

    def __init__(self, rule):
        self.rule = rule

    def apply_template(self, messages, kwargs=None):
        return messages[1]["content"]

    def complete(self, prompt, schema, n_predict, n_probs, cache_prompt=True):
        advisory = prompt.split("Weakness:\n", 1)[1].split("\n\nFunction", 1)[0]
        code = prompt.split("```\n", 1)[1].split("\n```", 1)[0]
        verdict, p = self.rule(advisory, code)
        tokens = ['{"verdict": "', verdict, '", "evidence": []}']
        alts = {"exhibits": p, "does_not_exhibit": (1 - p) * 0.9,
                "insufficient_context": (1 - p) * 0.1}
        steps = [{"token": t, "logprob": 0.0, "top_logprobs": []} for t in tokens]
        steps[1]["top_logprobs"] = [{"token": v, "logprob": math.log(max(q, 1e-9))}
                                    for v, q in alts.items()]
        return {"content": "".join(tokens), "completion_probabilities": steps,
                "tokens_evaluated": 100, "tokens_predicted": 3, "truncated": False}


def _own_text(pairs):
    texts, _ = perm.advisories(pairs, CATALOGUE)
    own = {}
    for f in perm.FRAMINGS:
        for k, t in texts[f].items():
            own[(f, k.split(":")[1])] = t
    return own


def reader(pairs):
    """Says exhibits only for vulnerable code under its own advisory, in either framing."""
    own = _own_text(pairs)

    def rule(advisory, code):
        name = code.split("(", 1)[0].split()[-1]
        mine = advisory in (own.get(("cwe", name)), own.get(("cve", name)))
        return ("exhibits", 0.9) if mine and "bad" in code else ("does_not_exhibit", 0.1)

    return rule


def blind(advisory, code):
    """Ignores the advisory: every vulnerable-looking function exhibits whatever it is told."""
    return ("exhibits", 0.8) if "bad" in code else ("does_not_exhibit", 0.3)


def _run(tmp_path, rule, pairs):
    items, meta = perm.plan(pairs, CATALOGUE)
    runs = {}
    for cand in (perm.PRIMARY, perm.SECOND):
        out = tmp_path / f"{cand}.jsonl"
        perm.execute(FakeModel(rule), items, out, "sha")
        runs[cand] = perm.load_runs(out)
    return perm.summarise(runs, items, meta)


def test_a_model_that_reads_the_advisory_passes(tmp_path):
    pairs = _pairs(120)
    s = _run(tmp_path, reader(pairs), pairs)
    cwe_sum = s["summaries"][perm.PRIMARY]["cwe"]
    assert cwe_sum["flip_rate"]["estimate"] == 1.0 and cwe_sum["band"] == "pass"
    assert s["reading"]["pre_registered_outcome"] == "PASS"
    assert cwe_sum["model_arm"]["pairwise_correct"]["estimate"] == 1.0
    assert cwe_sum["model_arm"]["precision_at_recall_0_70"]["estimate"] == 1.0


def test_a_model_that_ignores_the_advisory_fails(tmp_path):
    pairs = _pairs(120)
    s = _run(tmp_path, blind, pairs)
    assert s["summaries"][perm.PRIMARY]["cwe"]["flip_rate"]["estimate"] == 0.0
    assert s["summaries"][perm.PRIMARY]["cwe"]["band"] == "fail"
    assert s["reading"]["pre_registered_outcome"] == "FAIL"


def test_a_half_reader_is_ambiguous_and_falls_back_to_the_second_candidate(tmp_path):
    pairs = _pairs(120)
    read = reader(pairs)
    def half(adv, code):  # reads the advisory for even-numbered functions only
        n = int(code.split("(", 1)[0].split()[-1][1:])
        return read(adv, code) if n % 2 == 0 else blind(adv, code)

    s = _run(tmp_path, half, pairs)
    assert s["reading"]["primary_band"] == "ambiguous"
    assert s["reading"]["pre_registered_outcome"].startswith("FAIL (ambiguous")


def test_framings_exclude_and_count_what_they_cannot_frame():
    pairs = _pairs(70)
    _, meta = perm.plan(pairs, CATALOGUE)
    assert meta["excluded"]["cwe"]["missing_or_placeholder"] == 7  # i = 0, 10, ..., 60
    assert meta["excluded"]["cve"]["no_text"] == 10  # i % 7 == 3
    assert meta["eligible"] == {"cwe": 63, "cve": 60}


def test_the_draw_is_the_full_pool_never_self_never_identical_text():
    texts = {f"k{i}": f"CWE-{i % 3}" for i in range(30)}
    partner = perm.draw(texts, "cwe")
    assert all(partner[k] != k and texts[partner[k]] != texts[k] for k in texts)
    assert partner == perm.draw(texts, "cwe")  # seeded
    # Two different CWE texts are possible partners of k0 (CWE-1 and CWE-2): both get drawn.
    assert {texts[p] for p in partner.values()} == {"CWE-0", "CWE-1", "CWE-2"}


def test_the_identity_control_counts_changed_verdicts(tmp_path):
    pairs = _pairs(60)
    items, meta = perm.plan(pairs, CATALOGUE)
    out = tmp_path / "x.jsonl"
    perm.execute(FakeModel(blind), items, out, "sha")
    runs = perm.load_runs(out)
    flipped = 0
    for i in items:  # corrupt the control: flip three identity answers
        if i.role == "vuln_identity" and i.framing == "cwe" and flipped < 3:
            runs[i.key]["verdict"] = "does_not_exhibit"
            flipped += 1
    v = perm._verdicts(runs, items)
    keys = list(dict.fromkeys(i.pair for i in items if i.framing == "cwe"))
    assert perm.identity_control(v, keys, "cwe")["verdict_changes"] == 3


def test_an_incomplete_run_is_refused(tmp_path):
    pairs = _pairs(30)
    items, meta = perm.plan(pairs, CATALOGUE)
    out = tmp_path / "p.jsonl"
    perm.execute(FakeModel(blind), items[:-1], out, "sha")
    runs = {perm.PRIMARY: perm.load_runs(out), perm.SECOND: perm.load_runs(out)}
    with pytest.raises(SystemExit, match="unanswered"):
        perm.summarise(runs, items, meta)


def test_a_run_resumes_without_asking_twice(tmp_path):
    pairs = _pairs(20)
    items, _ = perm.plan(pairs, CATALOGUE)
    out = tmp_path / "r.jsonl"
    assert perm.execute(FakeModel(blind), items[:10], out, "sha") == 10
    assert perm.execute(FakeModel(blind), items, out, "sha") == len(items) - 10
    assert len(out.read_text().splitlines()) == len(items)


def test_unreadable_answers_are_recorded_not_fatal(tmp_path):
    class Broken(FakeModel):
        def complete(self, *a, **k):
            return {"content": "nonsense", "completion_probabilities": [],
                    "tokens_evaluated": 1, "tokens_predicted": 1}

    pairs = _pairs(5)
    items, _ = perm.plan(pairs, CATALOGUE)
    out = tmp_path / "b.jsonl"
    perm.execute(Broken(blind), items, out, "sha")
    recs = [json.loads(line) for line in out.read_text().splitlines()]
    assert all("error" in r for r in recs)


def test_the_pre_registered_constants_match_the_register():
    import yaml

    from anvil_eval import REGISTER_PATH

    row = next(r for r in yaml.safe_load(REGISTER_PATH.read_text())["experiments"]
               if r["id"] == perm.ID)
    assert "above 80%" in row["threshold_pass"] and "below 50%" in row["threshold_fail"]
    assert (perm.PASS_ABOVE, perm.FAIL_BELOW) == (0.80, 0.50)
    assert "12,000 characters" in row["method"] and primevul.MAX_FUNC_CHARS == 12_000
    assert "seed 20261003" in row["method"] and "10,000 resamples" in row["metric"]
    assert adjudicator.VERDICTS == ("exhibits", "does_not_exhibit", "insufficient_context")


def test_the_cwe_framing_decides_not_the_cve_framing(tmp_path):
    """A model that reads CWE text but not CVE text: the Lane-B-shaped number decides."""
    pairs = _pairs(120)
    read = reader(pairs)

    def cwe_only(advisory, code):
        return read(advisory, code) if advisory.startswith("CWE-") else blind(advisory, code)

    s = _run(tmp_path, cwe_only, pairs)
    assert s["summaries"][perm.PRIMARY]["cwe"]["band"] == "pass"
    assert s["summaries"][perm.PRIMARY]["cve"]["band"] == "fail"
    assert s["reading"]["pre_registered_outcome"] == "PASS"
