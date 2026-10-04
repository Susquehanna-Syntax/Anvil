"""Planted for Lane B's fixture: a test tree, excluded by the selection. Never run."""
import sys


def test_expression():
    assert eval(sys.argv[1])
