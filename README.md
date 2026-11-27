# 🛡️ polinrider-guard

**Find, report on and clean PolinRider supply-chain malware in your GitHub repositories and on your computer.**

[![npm](https://img.shields.io/npm/v/polinrider-guard)](https://www.npmjs.com/package/polinrider-guard)
[![CI](https://github.com/Gowreesh-VT/polinrider-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Gowreesh-VT/polinrider-guard/actions/workflows/ci.yml)
![Node.js 20+](https://img.shields.io/badge/node-%3E%3D20-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

[Quick start](#-quick-start) · [Commands](#-commands) · [If you were infected](#-if-you-were-infected) · [Docs](#-docs)

---

## What is PolinRider?

Malware that travels through git repositories. It:

- 🫥 **hides** in project files: padded config files, a hidden `init` file, `package.json` hooks and VS Code tasks that run when a folder is opened
- 🔑 **steals** credentials from the machine that runs it
- 🔁 **spreads** when an infected machine force-pushes rewritten commits to shared repos

## What you get

| | |
|---|---|
| 🔍 **Scan** | Every branch of every repo you can access, plus a history search for malware that was removed later |
| 🕵️ **Trace** | Who force-pushed what, and when |
| 💻 **Check** | A read-only look at your own computer |
| 🧹 **Clean** | One reviewable commit per branch, never a force-push, with undo |
| 🔒 **Private** | Runs locally with your `gh` login. No telemetry |

## 🚀 Quick start

You need **Node.js 20+**, **git** and the **[GitHub CLI](https://cli.github.com)**.

```bash
npm install -g polinrider-guard
```

```bash
gh auth login
```

```bash
polinrider-guard doctor
```

```bash
polinrider-guard report --all-accounts --quick
```

The tool uses your `gh` login, so it never asks for or stores a password or token.

<details>
<summary>Installing the GitHub CLI, more accounts, or building from source</summary>

- **macOS:** `brew install gh`
- **Windows:** `winget install --id GitHub.cli`
- **Linux:** see the [install instructions](https://github.com/cli/cli#installation)

When signing in, choose GitHub.com, HTTPS, and log in with the browser. To scan a second account, run `gh auth login`
again and sign in as that account. `--all-accounts` uses every signed-in account.

From source:

```bash
git clone https://github.com/Gowreesh-VT/polinrider-guard.git
cd polinrider-guard && npm install && npm run build
```

Then `npm link` (or run `node dist/cli.js` instead of `polinrider-guard`).

</details>

## 🧭 Commands

| Command | What it does | Changes anything? |
|---|---|---|
| `doctor` | Says what is missing from your setup and how to fix it | No |
| `host` | Checks this computer | No |
| `scan <dir>` | Scans a local folder or git repo | No |
| `report` | Scans GitHub repos and writes a report | No |
| `clean` | Shows what it would remove (dry run) | No |
| `clean --apply` | Commits the fixes | **Yes** |
| `clean --undo` | Shows what it would revert (dry run) | No |
| `clean --undo --apply` | Reverts earlier cleanups | **Yes** |

### Scan

```bash
# Everything, with the computer check included
polinrider-guard report --all-accounts --host

# One account, skipping an organisation
polinrider-guard report --account me --exclude some-org/

# One repo, or anyone's public repos (no sign-in needed)
polinrider-guard report --repo owner/name
polinrider-guard report --user someone
```

| Mode | Checks | Disk use |
|---|---|---|
| Full (default) | Every branch and old history | Keeps a cache in `~/.cache/polinrider-guard` |
| `--quick` | Newest commit of each branch only | Temporary clones, deleted after each repo |
| `--no-history` | Skips the history search | Same cache as full |

Reports go to `reports/` as `report.html`, `report.md` and `report.json`: findings per branch, the commit that first
added each one (full mode), every force-push (who, when, before and after) and which accounts keep force-pushing.

### Clean

```bash
polinrider-guard clean --repo owner/name            # preview
polinrider-guard clean --repo owner/name --apply    # fix
```

Example preview:

```text
owner/app
  main
    clean  .gitignore  [gitignore-config-bat]
    delete init  [init-file]
    clean  package.json  [package-hook]
    clean  postcss.config.mjs  [padded-payload]

4 file change(s) on 1 branch(es) in 1 repo(s); 0 item(s) need a human.
Dry run: nothing was changed. Run again with --apply to commit these fixes.
```

**Safety rules the cleaner follows**

- One commit per branch, never a force-push. A pull request instead when a branch is protected.
- Every change is read back to verify it.
- Anything it is not sure about (for example a folder-open task that runs a normal script) is listed for a human.
- A file named by a malicious task is deleted only if it really is a fake font.
- Repos you cannot write to are reported, not touched.
- Each commit is recorded in a local journal, so `clean --undo` can revert it as a new commit. This works only while
  the cleanup is still the branch tip, so later work is never lost.

## 💻 What the computer check looks at

- The hidden `~/.node_modules` folder, and node processes running font files or `init`
- Connections to reported malicious addresses
- Startup items, cron and shell profiles that download and run code (macOS, Linux, Windows)
- Dropper files and hidden folders a public report lists as dropper locations (`~/.n2`, `~/.npl`, ...)
- Shell history entries tied to the malware
- VS Code automatic tasks, reported malicious npm packages and infected project folders

It also lists the credentials a stealer could read.

> [!IMPORTANT]
> A clear result only means nothing was found right now. This malware can run once, steal what it can and remove itself.

## 🚨 If you were infected

Cleaning repos does not undo what was already stolen. **From a different, clean device:**

- [ ] Change your GitHub password and regenerate recovery codes
- [ ] Revoke sessions, authorized OAuth apps and personal access tokens
- [ ] Remove unknown SSH keys
- [ ] Rotate every secret that was on the machine (`.env` files, npm and cloud keys, saved browser passwords)
- [ ] Set `task.allowAutomaticTasks` to `"off"` in VS Code, so a repo cannot run code just by being opened

## 🔁 Stop it coming back

A cleaned branch can be overwritten again while anyone with write access is still infected or has a stolen token.

> [!WARNING]
> The replacement commit can reuse the author name, parent and timestamp of your cleanup commit. Check who
> force-pushed, not who the commit says wrote it.

1. Ask everyone who force-pushed to stop pushing, run `polinrider-guard host`, and revoke their tokens and SSH keys
   from a clean device.
2. Block force-pushes on your branches (branch protection or rulesets), and remove write access for accounts you cannot
   yet trust. Blocking force-pushes does not stop an infected account from pushing ordinary commits.
3. Clean, then scan the same repos again a day or two later:
   `polinrider-guard report --repo owner/name --quick`
4. Re-clone old local copies, or fetch and reset them to the cleaned branch, before running or pushing from them.
   Reset discards local changes, so save your own work first and check it for the same signs.

Cleaning adds a new commit and does not rewrite history, so older commits still contain the malware. Do not check
them out and run them.

## ⚠️ Limits

- Force-pushes show which account's credentials were used, not who was at the keyboard. The report says "consistent
  with", never "is infected"; confirm on the machine.
- New variants appear often. The scanner uses behaviour rules plus known signatures, so it can miss something new.
- Anonymous GitHub API use is limited to 60 calls an hour; signing in raises it. Force-push history needs a sign-in.
- The Windows and Linux computer checks are covered by unit tests but have had less real-world use than macOS.
- The malicious npm package names were checked against the registry (they are now security stubs or removed). The IP
  addresses are from public reports and not independently verified, so a match is reported as medium, not proof.
- Text from repositories is treated as untrusted: it is stripped of terminal escape codes and escaped in reports, and
  the GitHub token is only ever sent to api.github.com.
- Reports can name private repos, so keep them to yourself.

## 📚 Docs

| | |
|---|---|
| [Rules](docs/RULES.md) | What each finding means |
| [How it works](docs/HOW-IT-WORKS.md) | Design of the scanner and cleaner |
| [If infected](docs/IF-INFECTED.md) | Recovery steps in detail |
| [Status](docs/PLAN.md) | What is done and what is planned |

Test fixtures are defanged.

## 🛠️ Develop

```bash
npm test        # vitest
npm run build   # tsc
```

## License

[MIT](LICENSE)
