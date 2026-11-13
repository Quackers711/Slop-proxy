# slopproxy

Keeps secrets and sensitive names out of what a coding agent sends to the Claude API.

slopproxy sits between the agent harness (e.g. Claude Code) and the API. On the way
out it replaces secret values and renamed words in everything the model sees: file
reads, command output, instructions. On the way back it restores the real values
in tool inputs, so edits and commands work on the real files, and in the reply
text, so you read the real names. Every request masks the whole conversation
again, so restored text never reaches the model. Thinking is left as the model
wrote it, because it is signed. Files on disk are never changed by the proxy.

## Usage

```sh
go build -o slopproxy .
cd ~/work/my-project
slopproxy init           # creates ~/.config/slopproxy/projects/my-project
slopproxy scan           # lists what will be masked (never prints values)
slopproxy run -- claude  # runs Claude Code through a private proxy
```

Install it on your PATH with `go install .` (it lands in `~/go/bin`).

`slopproxy serve` runs on a fixed address (`-listen`, default `127.0.0.1:8787`) for
setting `ANTHROPIC_BASE_URL` yourself. `-log FILE` writes the proxy log.

Requests are forwarded to wherever Claude Code would have sent them: the
`ANTHROPIC_BASE_URL` in its settings files (`.claude/settings.local.json`,
`.claude/settings.json`, `~/.claude/settings.json`), else the one in the
environment, else `https://api.anthropic.com`. `-upstream URL` overrides it. Both
`run` and `serve` print where they forward to.

Claude Code lets the `env` in its settings files override its environment, so
`run -- claude` also passes the proxy's address with `--settings`, which only
managed (enterprise) settings outrank. slopproxy warns if those set
`ANTHROPIC_BASE_URL`, or if you pass your own `--settings`.

## Traffic view

```sh
slopproxy -view run -- claude
```

`-view` (with `run` or `serve`) opens a live page in your browser that shows
everything passing through the proxy:

- **Rewrites:** every value hidden from Anthropic in a request (secrets and
  `[names]`, with how often), and every tool call or reply whose stand-ins were
  turned back into real values.
- **Request:** exactly what was sent to Anthropic, as a conversation or raw
  JSON, with the stand-ins highlighted.
- **Response:** what Anthropic sent back, with each restored tool call or reply
  shown side by side: what the model wrote, and what you and the agent got.
- **Headers:** both directions. Credentials (`x-api-key`, `authorization`,
  cookies) are never recorded.

Real values stay dotted out until you tick **Reveal real values**. The page
needs the one-time link printed in your terminal, because the agent can reach
`localhost` too. Everything is kept in memory only (the newest 100 requests, up
to 64 MB) and is gone when slopproxy exits.

## Config

The config lives outside the project, so the agent doesn't stumble on it. The first
one found wins: `-config FILE`, `~/.config/slopproxy/projects/<folder name>`,
`~/.config/slopproxy/config`.

```ini
[values]                          # hide the value assigned to these
DB_PASSWORD = not-the-real-db-password
GITHUB_TOKEN                      # agent sees [[SECRET:GITHUB_TOKEN]]
*_SECRET                          # every matching variable

[files]                           # read [values] from these too; .env always is
config/secrets.yml
.env.*

[names]                           # rename these words themselves
calculateRiskScore = scoreThing

[hosts]                           # serve a remote host as a localhost one
https://api.acme.com = 9001       # the agent sees http://localhost:9001
  strip-cf
  request Authorization: Bearer $ACME_TOKEN
```

- `[values]`: values come from the environment and from assignments (`NAME=x`,
  `NAME: x`, `"NAME": "x"`, `NAME := x`, ...) in `.env` and the files under
  `[files]` (paths relative to the project, globs allowed). Nothing else in the
  project is read, so startup is instant in any repo. Names match
  case-insensitively. Values shorter than 8 characters are skipped with a warning,
  and a name whose value isn't found gets a warning on every start.
- `slopproxy scan -all` searches every file git sees (plus ignored files like
  `.env.local`, but not ignored folders like `node_modules`) and lists the files
  to add under `[files]`.
- `[names]`: renamed wherever they appear as a whole word, so `key` does not touch
  `keyboard` or `VALID_KEY`. Any literal string works, including a secret value:
  write `NAME = replacement` with spaces around `=` if it contains `=` itself.
- `[names]` match in any case, and the replacement takes the casing of the text
  it replaces. What the agent writes is mapped back the same way:

  | Rule | Text | Agent sees |
  | --- | --- | --- |
  | `banana = apple` | `banana` / `Banana` / `BANANA` | `apple` / `Apple` / `APPLE` |
  | `some = tobe` | `SoMe` | `ToBe` (other mixed case is copied letter by letter) |
  | `calculateRiskScore = scoreThing` | `calculateRiskScore` / `CalculateRiskScore` | `scoreThing` / `ScoreThing` |

  Text written exactly like the rule gets the replacement exactly as written.
  Mixed case like `SoMe` only maps back exactly when both words are the same
  length.

Upgrading from a version that searched the whole project: configs keep working
unchanged, but `[values]` assigned only in files other than `.env` now produce a
"no value found" warning until you list those files under `[files]`.
- Replacements must be unique and not appear in the project: whatever the agent
  writes is swapped back to the real thing.
- Well-known token formats (Anthropic, OpenAI, GitHub, AWS, Stripe, Slack, Google,
  JWTs, PEM private keys) are always masked, no config needed.

## Cloaked hosts

`[hosts]` makes a remote service look like a local one. With `run` or `serve`,
slopproxy listens on `localhost:PORT` for each host and forwards to the real
one, and everywhere the model looks, the real address reads as the local one.
Option lines belong to the host above them (indenting them is optional):

```ini
[hosts]
https://api.acme.com = 9001                   # no scheme means https://
  strip-cf                                    # drop Cloudflare headers both ways
  request Authorization: Bearer $ACME_TOKEN   # set a request header
  request -X-Forwarded-For                    # remove one; -x-trace-* removes a prefix
  response -Server                            # the same for responses
  response X-Frame-Options: DENY
  insecure                                    # don't verify the target's certificate
```

**What the model sees.** `https://api.acme.com/v1` becomes
`http://localhost:9001/v1`, `api.acme.com` alone becomes `localhost:9001`, and
subdomains and e-mail addresses follow (`cdn.localhost:9001`,
`ops@localhost:9001`). Thinking is left alone, as always.

**What comes back.** File edits and other tools get the real address back, so
`Edit` matches what is on disk. Tools that reach the network (`Bash`,
`PowerShell`, `Monitor`, `WebFetch`) keep `localhost:9001`, so their requests go
through the cloak and get its headers. A side effect: `grep localhost:9001` in a
`Bash` command searches for the local address, not the real one. Reply text is
restored, so you read the real host.

**The traffic.** The target gets a normal request for its own host name. The
cloak maps the address both ways in headers (`Location`, `Origin`, `Referer`,
...), the query string, and text bodies up to 8 MB (JSON, HTML, XML, form data,
...). It drops `Domain` from cookies and removes `Strict-Transport-Security` and
`Alt-Svc`, which would send a client back to the real host. Your header rules
run last, so they win.

- `strip-cf` removes `cf-*`, `CDN-Loop` and `True-Client-IP` from requests, and
  `cf-*` (`CF-Ray`, `CF-Cache-Status`, ...) from responses, plus `Server`,
  `NEL`, `Report-To`, `Reporting-Endpoints`, `Speculation-Rules` and `Expect-CT`
  when they point at Cloudflare. Cloudflare's cookies (`__cf_bm`,
  `cf_clearance`) stay: without them its bot protection blocks every request.
- `$VAR` and `${VAR}` in header values come from the environment, else from
  `[values]` found in `.env` and `[files]`. Values of 8+ characters are masked
  like any secret, so a token the cloak adds never reaches the model.
- `localhost:PORT` already in the project gets a warning: if the agent edits it,
  it becomes the real host.

Streams (`text/event-stream`), larger bodies and compressed request bodies pass
through with the real address in them; WebSockets are proxied but their
messages are not rewritten. The model sees all of it masked anyway.

## Limits

- Protects what the model sees, not what the agent can do: it can still run
  `curl -d @.env`, or reach a cloaked host directly. Pair with a sandbox if that
  matters.
- Transformed secrets (`base64`, `cut -c1-10`) pass through.
- Short, common words in `[names]` get renamed everywhere, including in prose and
  in the agent's own instructions.
- Claude API only.
