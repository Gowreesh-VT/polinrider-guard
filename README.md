# polinrider-guard

Find, report on and clean **PolinRider** supply-chain malware in your GitHub repositories and on your computer.

PolinRider hides code in project files (padded config files, a hidden `init` file, `package.json` hooks, VS Code
tasks that run when a folder is opened), steals credentials, and spreads when an infected machine force-pushes
rewritten commits to shared repos. This tool looks for all of that, shows who force-pushed what, and can remove it.

## Getting started

You need Node.js 20+, git, and the GitHub CLI (`gh`). The tool uses your `gh` login, so it never asks for or stores a password or token.

1. **Install the GitHub CLI** ([cli.github.com](https://cli.github.com))
   - macOS: `brew install gh`
   - Windows: `winget install --id GitHub.cli`
   - Linux: see the [install instructions](https://github.com/cli/cli#installation)
2. **Sign in**: `gh auth login` and choose GitHub.com, HTTPS, and log in with the browser.
   To scan a second account, run `gh auth login` again and sign in as that account. Every signed-in account is used.
3. **Get the tool**
   ```bash
   npm install -g polinrider-guard   # installs the `polinrider-guard` command
   ```
   Or from source:
   ```bash
   git clone https://github.com/Gowreesh-VT/polinrider-guard.git
   cd polinrider-guard && npm install && npm run build
   ```
   Then `npm link` (or run `node dist/cli.js` instead of `polinrider-guard`).
4. **Check your setup**: `polinrider-guard doctor` tells you what is missing and how to fix it.

## Use

```bash
# 1. Is this computer affected? Read-only; never runs anything it finds.
polinrider-guard host

# 2. Scan every repo of every account you are signed in to, with a detailed report
polinrider-guard report --all-accounts --host

# Only some accounts / repos, skip organisations, or scan anyone's public repos (no sign-in needed)
polinrider-guard report --account me --exclude some-org/
polinrider-guard report --repo owner/name
polinrider-guard report --user someone

# Faster, shallower scan: newest commit of each branch only, nothing kept on disk (no history scan, no "first added")
polinrider-guard report --all-accounts --quick

# 3. Remove the malware. Dry run by default: it prints exactly what it would change.
polinrider-guard clean --all-accounts
polinrider-guard clean --all-accounts --apply

# 4. Changed your mind? Revert the cleanup commits made from this machine (also a dry run until --apply)
polinrider-guard clean --undo
polinrider-guard clean --undo --apply
```

Reports are written to `reports/` as `report.html`, `report.md` and `report.json`: findings per branch, the commit that
first added each one (the history scan also finds malware that was added and later removed; skip it with `--no-history`), every force-push (who, when, before and after), and which accounts keep force-pushing.

### What the computer check looks at

The hidden `~/.node_modules` folder, node processes running font files or `init`, connections to known malicious
addresses, startup items, cron and shell profiles that download and run code (macOS, Linux, Windows), dropper files,
VS Code automatic tasks, reported malicious npm packages, and infected project folders. It also lists credentials a
stealer could read. **A clear result only means nothing was found right now**: this malware can run once, steal what it
can and remove itself.

### What the cleaner does

One commit per branch, never a force-push; a pull request instead when a branch is protected; every change is read
back to verify it. It skips anything it is not sure about (for example a folder-open task that runs a normal script)
and lists it for a human. It only deletes a file named by a malicious task if that file really is a fake font. Repos you
cannot write to are reported, not touched. Each commit is recorded in a local journal so `clean --undo` can revert it
as a new commit (only while the cleanup is still the branch tip, so later work is never lost).

## If you were infected

Cleaning repos does not undo what was already stolen. From a different, clean device: change your GitHub password,
revoke sessions, authorized OAuth apps and personal access tokens, regenerate recovery codes, remove unknown SSH keys,
and rotate any secret that was on the machine (`.env` files, npm and cloud keys, saved browser passwords).
Set `task.allowAutomaticTasks` to `"off"` in VS Code so a repo cannot run code just by being opened.

## Notes and limits

- Force-pushes show which account's credentials were used, not who was at the keyboard. The report says "consistent
  with", never "is infected"; confirm on the machine.
- New variants appear often. The scanner uses behaviour rules plus known signatures, so it can miss something new.
- Anonymous GitHub API use is limited to 60 calls an hour; signing in raises it. Force-push history needs a sign-in.
- The Windows and Linux computer checks are covered by unit tests but have had less real-world use than macOS.
- Indicators: the malicious npm package names were checked against the registry (they are now security stubs or removed); the IP addresses are from public reports and not independently verified, so a match is reported as medium, not proof.
- Text from repositories is treated as untrusted: it is stripped of terminal escape codes and escaped in reports, and the GitHub token is only ever sent to api.github.com.
- Everything runs locally. No telemetry. Reports can name private repos, so keep them to yourself.

Docs: [rules](docs/RULES.md), [how it works](docs/HOW-IT-WORKS.md), [if you were infected](docs/IF-INFECTED.md), [status](docs/PLAN.md). Test fixtures are defanged.

## Develop

```bash
npm test        # vitest
npm run build   # tsc
```

MIT licensed.
