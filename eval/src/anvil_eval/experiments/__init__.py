"""The Phase 5 experiments, one module per register row they produce.

Each module has a ``run`` step that does the expensive work (owner-run where it needs a GPU) and a
``report`` step that turns its raw output into ``eval/results/<id>.json``. A report refuses a run
that does not cover its whole pre-registered sample, and no artifact is written unless its
negative control passed.
"""
