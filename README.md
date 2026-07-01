# 🛡️ PromptGuard

**A lightweight, privacy-first AI prompt scanner that runs 100% in your browser.**

PromptGuard scans text *before* you paste it into ChatGPT, Claude, Gemini, Copilot, Grok, DeepSeek, or any local LLM, flagging API keys, passwords, personal data, connection strings, prompt-injection phrasing, and more — without ever sending a single byte over the network.

> No server. No backend. No cloud API. No analytics. No cookies. No tracking.
> It's just `index.html`, three small JS modules, and your browser's JavaScript engine.

---

## Table of Contents

- [Why PromptGuard](#why-promptguard)
- [Features](#features)
- [What it detects](#what-it-detects)
- [Privacy Score](#privacy-score)
- [Installation](#installation)
- [Deploying on GitHub Pages](#deploying-on-github-pages)
- [Self-hosting](#self-hosting)
- [Usage Guide](#usage-guide)
- [Project Structure](#project-structure)
- [Privacy Policy](#privacy-policy)
- [Contributing](#contributing)
- [Roadmap Ideas](#roadmap-ideas)
- [License](#license)

---

## Why PromptGuard

Copy-pasting logs, code, or notes into an AI chat is incredibly easy to do without
thinking — and incredibly easy to accidentally leak an API key, a customer's
email, or a database connection string while doing it. PromptGuard is a small,
inspectable tool you can run **completely offline** to catch that before you hit
send.

## Features

- 🔒 **Fully offline** — works with no internet connection at all once the page is loaded (or even self-hosted from disk).
- 🧠 **Local regex + heuristic scanning** — no AI model, no API calls, no telemetry.
- 🎯 **20+ detection categories** — secrets, credentials, PII, connection strings, hidden Unicode, prompt-injection & jailbreak phrasing.
- 📊 **Privacy Score (0–100)** with a clear Safe → Critical scale.
- 🟢🟡🔴 **Color-coded finding cards** with category, severity, matched value, line number, and a fix-it recommendation.
- ✂️ **One-click REDACT** — replaces sensitive values with placeholders like `[EMAIL]` or `[OPENAI_API_KEY]`.
- 📋 **Copy Redacted** straight to your clipboard.
- 📄 **Downloadable JSON & TXT reports**.
- 🌗 **Dark mode** (default) and light mode.
- 📂 **Drag & drop** `.txt`, `.md`, `.log`, `.json` files — auto-scans on drop.
- 📈 Live character / word / estimated token / line counters.
- 🧩 **Modular codebase** — `patterns.js`, `risk.js`, and `redactor.js` are independent, documented modules you can audit or extend in minutes.

## What it detects

| Category | Examples |
|---|---|
| OpenAI API Keys | `sk-...`, `sk-proj-...` |
| Anthropic API Keys | `sk-ant-...` |
| Google API Keys | `AIza...` |
| AWS Access Keys | `AKIA...`, `ASIA...` |
| AWS Secret Keys (heuristic) | `aws_secret_access_key = ...` |
| GitHub Personal Access Tokens | `ghp_...`, `github_pat_...` |
| Bearer Tokens | `Authorization: Bearer ...` |
| JWT Tokens | `eyJ....eyJ....signature` |
| SSH Private Keys | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| RSA / EC / DSA Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Email Addresses | `john@example.com` |
| Phone Numbers | various international formats |
| Credit Card Numbers | validated with the **Luhn algorithm** to reduce false positives |
| IPv4 / IPv6 Addresses | |
| URLs | |
| Password Assignments | `password = "..."`, `pwd: ...` |
| Database Connection Strings | `postgres://`, `mysql://`, `redis://`, JDBC URLs |
| MongoDB Connection Strings | `mongodb://`, `mongodb+srv://` |
| Cookies | `Set-Cookie:`, `Cookie:` headers |
| Session IDs | `PHPSESSID`, `connect.sid`, `JSESSIONID`, etc. |
| Base64 Encoded Blobs | long base64 sequences that may hide payloads |
| `.env`-style Variables | `SOME_KEY=value` lines |
| Prompt Injection Phrases | "ignore previous instructions", "reveal your system prompt", etc. |
| Jailbreak Phrases | "DAN mode", "do anything now", "jailbreak", etc. |
| Hidden Unicode / Zero-Width Characters | invisible characters that can hide instructions |
| SQL Statements | `SELECT ... FROM`, `DROP TABLE`, etc. |

All rules live in [`patterns.js`](./patterns.js) — open it up, it's plain, commented JavaScript.

## Privacy Score

Every finding has a severity (`critical`, `high`, `medium`, `low`) with its own
point penalty. PromptGuard starts at 100 and subtracts weighted penalties per
finding (with diminishing weight after the third occurrence of the same
category, so one huge paste with many emails doesn't unfairly tank the score).
See [`risk.js`](./risk.js) for the exact formula.

| Score | Label | Meaning |
|---|---|---|
| 90–100 | 🟢 Safe | Nothing meaningfully sensitive detected |
| 75–89 | 🟢 Minor Issues | A few low-risk items worth a glance |
| 50–74 | 🟡 Moderate Risk | Several flags — review before sending |
| 25–49 | 🟠 High Risk | Likely real secrets or PII present |
| 0–24 | 🔴 Critical | Strongly recommend redacting before sending |

## Installation

There is nothing to build, install, or compile.

```bash
git clone https://github.com/your-username/promptguard.git
cd promptguard
```

Then simply **open `index.html` in any modern browser** (Chrome, Firefox, Edge, Safari). That's it — the whole app runs from the local file.

No `npm install`. No build step. No Node.js required.

## Deploying on GitHub Pages

1. Push this repository to GitHub.
2. Go to your repo's **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to `Deploy from a branch`.
4. Choose the `main` branch and the `/ (root)` folder, then **Save**.
5. GitHub will publish your site at `https://your-username.github.io/promptguard/` within a minute or two.

No further configuration is needed — PromptGuard has no backend, no environment variables, and no build pipeline.

## Self-hosting

Because it's static files, PromptGuard can be hosted absolutely anywhere:

- Any static web host (Netlify, Vercel, Cloudflare Pages, S3 + CloudFront, your own nginx box)
- A company intranet for internal, air-gapped use
- Directly from your filesystem (`file:///path/to/promptguard/index.html`) with zero hosting at all

Since everything runs client-side, you can even disconnect from the internet entirely after the page first loads and continue using every feature.

## Usage Guide

1. **Paste** your prompt into the text box, or **drag & drop** a `.txt`, `.md`, `.log`, or `.json` file onto it (dropped files scan automatically).
2. Click **SCAN** (or press `Ctrl`/`Cmd` + `Enter`).
3. Review your **Privacy Score** and the list of color-coded findings — each card shows the category, severity, matched value, line number, and a recommendation.
4. Click **REDACT** to generate a sanitized copy with sensitive values swapped for placeholders like `[EMAIL]` or `[GITHUB_TOKEN]`.
5. Click **Copy Redacted** to copy the sanitized text to your clipboard, ready to paste into your AI tool of choice.
6. Optionally download a **JSON** or **TXT** report for your own records or for sharing with a security reviewer.
7. Toggle **dark/light mode** with the 🌙/☀️ button in the header — your preference is remembered locally (`localStorage`), never synced anywhere.

## Project Structure

```
promptguard/
├── index.html      # App shell & markup
├── style.css        # Design system: dark/light themes, layout, components
├── app.js           # UI orchestration: scanning flow, rendering, events
├── patterns.js       # Detection rules: regex patterns + phrase lists
├── risk.js           # Privacy Score calculation
├── redactor.js        # Redaction + clipboard helpers
├── README.md
└── LICENSE
```

The four logic modules are deliberately decoupled:

- **`patterns.js`** — pure data + small pure functions (Luhn check, phrase matching). No DOM access.
- **`risk.js`** — pure scoring function, takes findings in, returns a score object out.
- **`redactor.js`** — pure text-transform + a clipboard helper. No DOM rendering.
- **`app.js`** — the only file that touches the DOM. It wires the three modules above into the UI.

This separation means you can reuse `patterns.js` + `risk.js` + `redactor.js` in a CLI tool, a browser extension, or a test suite without touching any UI code.

## Privacy Policy

PromptGuard's entire privacy policy, in full:

> **We don't collect anything, because there is no "we" to send it to.**

Specifically:

- No network requests are made by this application, ever (no fonts, no CDNs, no APIs).
- No analytics, telemetry, or error-reporting scripts are included.
- No cookies are set.
- The only thing PromptGuard writes to disk is your **dark/light mode preference**, stored in `localStorage` on your own device. Nothing else persists between sessions, and nothing is ever transmitted.
- Files you drag & drop are read with the browser's local `FileReader` API and never leave the page.
- You can verify all of this yourself — the entire codebase is four small, readable JavaScript files.

## Contributing

Contributions are very welcome, especially new detection patterns and false-positive fixes.

1. Fork the repository and create a branch: `git checkout -b feature/my-detector`.
2. Keep changes framework-free — plain HTML/CSS/JS only, no build step.
3. New detection rules go in `patterns.js`; new scoring logic goes in `risk.js`; redaction logic goes in `redactor.js`. Keep `app.js` focused on wiring, not rules.
4. Test by opening `index.html` directly in a browser — there's no build to run.
5. When adding a pattern, please include:
   - A clear `category` name and a `severity` (`critical` / `high` / `medium` / `low`)
   - A short, actionable `recommendation`
   - A `placeholder` for redaction
   - A few example inputs in your PR description, including edge cases that should *not* match
6. Open a Pull Request describing what you added and why.

Bug reports and pattern false-positive/false-negative reports are just as valuable as code — please open an issue with a (sanitized!) example string that should or shouldn't have matched.

## Roadmap Ideas

- Browser extension wrapper (Chrome/Firefox) for in-context scanning on ChatGPT/Claude pages
- Custom user-defined regex rules saved locally
- Per-category enable/disable toggles
- Export findings as CSV
- Optional local-only scan history (still no network, just `localStorage`/`IndexedDB`)

## License

MIT — see [LICENSE](./LICENSE).
