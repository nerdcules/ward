---
name: ward
description: Check which published CVEs affect this machine's installed packages and kernel, how each was triaged, and what would fix it, through the ward command. Use when asked whether this computer is affected by a CVE, which security updates matter, or whether a package or the kernel is vulnerable.
---

# ward

`ward` matches the installed pacman packages (and the kernel) against
CVE.org's records, Arch's security tracker and CISA's list of exploited
CVEs, works out what the machine uses, and has Claude triage the rest.
Every command exits 0 on success and 1 with the problem on stderr.

- `ward status --json`: the last check, without a new one. `findings` holds
  one object per CVE and package: `cve`, `package`, `version`, `verdict`
  (`affected`, or `unknown` when the record's versions can't be read),
  `match` (`tracker`, `vendor`, `name`: how sure the match is), `kev`,
  `score`, `fixedIn`, `updateTo` (a fixing update waiting in the repos),
  `where` (kernel only: `loaded`, `built-in`, `core`, `not-loaded`,
  `other-arch`, `unclear`), and triage's `applies` (`yes`, `no`, `unclear`),
  `priority` (`now`, `soon`, `later`), `why` and `triagedBy` (`claude` or
  `ward`). Untriaged findings have no `applies`. `kernels` says whether the
  kernel's branch is end-of-life; `exposure` has, per package, what runs it.
- `ward check --json [--no-triage] [--offline]`: a new check. It updates the
  CVE list (the first run downloads 669 MB once) and asks Claude about at
  most 10 batches of new findings; `--no-triage` asks nothing.
- `ward show <CVE-ID>`: one record, with every product and range it names.
- `ward fix <package>`: what would fix it. Ward prints commands and never
  runs them; run one only when the user asks.

Matches are by version, so a patched Arch build can still match; read
`applies` and `why` before telling the user they are exposed. Results live in
`~/.local/state/ward/findings.json`, Claude's answers in `triage.json`.
