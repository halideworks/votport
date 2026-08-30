# Workspace instructions

- Never use `/tmp` for temporary files, caches, worktrees, test data, downloads, or build artifacts.
- Use `/nvme-mirror/temp/claude/tmp` for all temporary storage and set `TMPDIR` to that path for tools that create temporary files implicitly.
- Preserve recoverable work when cleaning temporary storage. Delete only verified generated artifacts.
