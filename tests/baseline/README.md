# Frozen pre-change baseline

This is a snapshot of the engine immediately before the second anti-analysis
pass. It is used only by `tests/compare_versions.py` to benchmark the old and
improved implementations on the same inputs. It is not imported by production
code. `tools` is a symlink to the workspace's official Luau binaries.
