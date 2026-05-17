#!/usr/bin/env python3
"""Quick test for run_pipe_tool."""
import sys
import os

os.environ.setdefault("PYTHONPATH", r"C:\Users\maker\Desktop\Graduation\Graduation Project\Selectinfo-Restart")
sys.path.insert(0, os.environ["PYTHONPATH"])

from selectinf.core.tool_runner import run_pipe_tool, ToolResult
import inspect

# Verify signature
sig = inspect.signature(run_pipe_tool)
params = list(sig.parameters.keys())
print('run_pipe_tool params:', params)
assert 'cmd1' in params
assert 'cmd2' in params
assert 'description' in params
assert 'timeout' in params

# Test pipe execution: echo hello | cat
res = run_pipe_tool(
    cmd1=['python', '-c', 'print("hello")'],
    cmd2=['python', '-c', 'import sys; print(sys.stdin.read().strip())'],
    description='pipe-test',
    timeout=10
)
print('pipe result success:', res.success)
print('pipe result stdout:', res.stdout)
print('pipe result exit_code:', res.exit_code)
assert res.success == True
assert 'hello' in res.stdout

print('ALL PIPE TOOL CHECKS PASSED')
