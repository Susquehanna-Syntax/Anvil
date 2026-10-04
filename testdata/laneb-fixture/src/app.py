"""Planted for Lane B's fixture. Never run."""
import subprocess
import sys


def run_expression():
    return eval(sys.argv[1])


def run_command(cmd):
    return subprocess.call(cmd, shell=True)
