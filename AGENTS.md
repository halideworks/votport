# Workspace instructions

- Use `/nvme-mirror/temp/claude/tmp` for temporary files, caches, worktrees, test data, and build artifacts; export `TMPDIR`, `TMP`, and `TEMP` to it for tools and child processes.
- On remote hosts without that path, create an explicit scratch directory under the remote workspace or home (never `/tmp`) and export all three variables to it.
- Do not create `/tmp` artifacts. After work, inspect and remove only exact task-specific `/tmp` artifacts left by tools; preserve recoverable work and never delete platform/runtime files.
