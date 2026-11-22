# Detection rules

Every finding has a rule name, a severity and the evidence (file, line shape, branch). Severity decides the verdict:
**high** = infected, **medium** = suspicious, **low** = informational (shown, never counted).

## Repository rules

| Rule | Looks for | Severity |
|---|---|---|
| `padded-payload` | Code placed after 80+ spaces on a line (hiding it off-screen), or ~30 KB lines in config files | high |
| `init-file` | A hidden `init` file that a script runs with `node init` | high |
| `package-hook` | `node init &&` or similar loader in package.json lifecycle scripts | high |
| `package-scripts` | Loader-shaped lifecycle scripts (high); unknown lifecycle scripts, review/dep-from-URL (low) | high / low |
| `vscode-autorun` | `.vscode/tasks.json` task that runs when the folder opens, or `task.allowAutomaticTasks` | high |
| `decode-exec` / `env-loader` | Base64 or environment-variable decoded and passed to `eval`/`Function`/`exec` (`atob(process.env.AUTH_API_KEY)` style) | high |
| `env-loader-key` | The loader's key set in a `.env` file | high |
| `gitignore-config-bat` | `config.bat` or the dropper script name hidden in `.gitignore` | medium |
| `dropper-file` | Known dropper filenames present in the tree | high |
| `fake-binary` | A "font" or media file (.woff2, .ttf, .orc ...) that is really script text | high |
| `media-trailing-code` / `media-check` | Code appended after a real media file's end, or a known marker inside one | high |
| `known-signature` | Exact payload markers from reported samples (skips prose and `.gitignore`) | high |
| `known-bad-package` | Reported malicious npm names in dependencies | high |
| `eval-network` | `eval` of data fetched from the network | medium |
| `credential-access` | Reading browser stores, keychains or wallets | medium |
| `shell-download-exec` | `curl … | sh` style chains; strong forms high, plain installers low | high / low |
| `git-amend-force-push` | Scripts that amend the last commit and force-push (the spreading mechanism) | high in scripts, low in source |
| `suspicious-endpoint` | Paste/file-host endpoints used by samples | low |
| `devcontainer-hook`, `workflow-pr-target` | Hooks that run code automatically | low |
| `obfuscated` | Heavily obfuscated code | medium |

Fixture/test/example folders cap some rules to low. Vendored and bundled paths (`node_modules`, `vendor`, `venv`, `dist` ...)
are only checked for exact signatures.

## History scan

`git log -S` over all refs for known markers finds malware that was added and later removed. A trace in old commits
whose current files are clean is reported as history only: the repo is clean now, but anything that ran from it may
have been exposed. Disable with `--no-history`.

## Computer checks (`gitward host`)

Hidden `~/.node_modules`; `node` processes whose own command is a font/`init` file; connections to reported IPs
(medium, because the addresses are secondhand); launchd, cron, systemd, Windows Run keys, scheduled tasks and shell
profiles that download and run code; dropper files; VS Code automatic tasks; globally installed reported npm packages;
infected project folders. A separate list shows credentials a stealer could have read.

Verdict: **likely infected** needs a host-level high finding. Infected projects alone do not make the machine
"compromised", but should be cleaned.

## Indicators and how sure they are

- npm packages: `tailwind-mainanimation`, `tailwindcss-style-animate`, `tailwind-autoanimation`, `tailwind-animationbased`,
  `tailwindcss-typography-style`, `tailwindcss-style-modify` (now registry security stubs) and `tailwindcss-animate-style`
  (unpublished). Checked against the npm registry. Legitimate look-alikes (`tailwindcss-animate`, `tailwindcss-typography`) are excluded.
- IP addresses: from public reports, not independently verified. The command-and-control address differs between victims, so match behaviour, not one IP.

## Scanning this repository

The rule definitions (`src/core/rules`, `src/sources/history.ts`) and tests quote the indicators they detect, so
`gitward scan` on this repo reports findings in those files. They are not malware. We deliberately have no
"ignore me" marker, because malware could add one too.
