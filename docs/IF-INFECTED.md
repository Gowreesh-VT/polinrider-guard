# If you were infected

Cleaning repositories does not undo theft. Do this from a **different, clean device**:

1. Change your GitHub password; revoke all sessions, authorized OAuth apps and personal access tokens; regenerate recovery codes.
2. Remove unknown SSH keys and deploy keys; rotate your own SSH keys.
3. Rotate every secret that was on the machine: `.env` files, npm tokens, cloud keys (AWS etc.), saved browser passwords, crypto wallets.
4. On the infected computer: do not just delete files. Back up documents only, then reset or reinstall the OS if the host check says *likely infected*.
5. Re-clone repos afterwards; do not reuse old working folders.
6. Set `task.allowAutomaticTasks` to `"off"` in VS Code.
7. Find the source: the report's force-push table shows which collaborator account keeps re-infecting. Tell them to run `polinrider-guard host`.
8. Check the cleanup with `polinrider-guard report` again after a few days; re-infection usually comes from a collaborator's machine.
