# How it works

1. **Accounts.** `gh auth token --user NAME` for each signed-in account. The tool never stores a token; it goes to
   `api.github.com` and to git through environment variables, never on a command line.
2. **Mirrors.** Each repo is cloned bare into `~/.cache/gitward/repos` (folder mode 0700) and refreshed with
   fetch. Git is run with `core.fsmonitor`, hooks, pager and external protocols disabled so a hostile repo cannot run code.
3. **Scan.** Every branch tip is read straight from git objects (nothing is checked out or executed). Identical blobs
   on many branches are scanned once. Rules are bounded so adversarial files cannot stall the scan (fuzz tests).
4. **Attribution.** `git log --find-object` finds the commit that first introduced each blob. GitHub's activity API
   lists force-pushes (who, when, before/after). Because a force-push keeps the original author, the report credits the
   introduction to the force-push that created the commit. This identifies the account used, not the person or machine.
5. **Report.** HTML, Markdown and JSON in `reports/`. Untrusted text (paths, branch names, commit subjects) has
   control characters removed and is escaped.
6. **Clean.** The fix is planned from the local mirror, one commit per branch via the git trees API, fast-forward only.
   Protected branch: a `gitward/clean-…` branch plus a pull request. After writing, each file is read back and compared.
   Edits that would break JSON or leave the pattern are refused and listed as manual. Commits are journaled
   (`~/.cache/gitward/journal.jsonl`) for `clean --undo`.

Limits: API 5000 calls/hour signed in, 60 anonymous. The tool is read-only toward your computer and never runs scanned code.
