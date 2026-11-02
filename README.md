# slopproxy

Keeps secrets and sensitive names out of what a coding agent sends to the Claude API.

slopproxy sits between the agent harness (e.g. Claude Code) and the API. On the way
out it replaces secret values and renamed words in everything the model sees: file
reads, command output, instructions. On the way back it restores the real values
inside tool inputs only, so edits and commands work on the real files. Files on disk
are never changed by the proxy, and the chat shows exactly what the model saw.

## Usage

```sh
go build -o slopproxy .
cd ~/work/my-project
slopproxy init           # creates ~/.config/slopproxy/projects/my-project
slopproxy scan           # lists what will be masked (never prints values)
slopproxy run -- claude  # runs Claude Code through a private proxy
```

`slopproxy serve` runs on a fixed address (`-listen`, default `127.0.0.1:8787`) for
setting `ANTHROPIC_BASE_URL` yourself. `-log FILE` writes the proxy log.

## Config

The config lives outside the project, so the agent doesn't stumble on it. The first
one found wins: `-config FILE`, `~/.config/slopproxy/projects/<folder name>`,
`~/.config/slopproxy/config`.

```ini
[values]                          # hide the value assigned to these
DB_PASSWORD = not-the-real-db-password
GITHUB_TOKEN                      # agent sees [[SECRET:GITHUB_TOKEN]]
*_SECRET                          # every matching variable

[names]                           # rename these words themselves
calculateRiskScore = scoreThing
```

- `[values]`: every text file in the project is searched for assignments
  (`NAME=x`, `NAME: x`, `"NAME": "x"`, `NAME := x`, ...), and the environment is
  checked too. Names match case-insensitively. Values shorter than 8 characters are
  skipped with a warning.
- `[names]`: renamed wherever they appear as a whole word, case-sensitively, so
  `key` does not touch `keyboard` or `VALID_KEY`.
- Replacements must be unique and not appear in the project: whatever the agent
  writes is swapped back to the real thing.
- Well-known token formats (Anthropic, OpenAI, GitHub, AWS, Stripe, Slack, Google,
  JWTs, PEM private keys) are always masked, no config needed.

## Limits

- Protects what the model sees, not what the agent can do: it can still run
  `curl -d @.env`. Pair with a sandbox if that matters.
- Transformed secrets (`base64`, `cut -c1-10`) pass through.
- Short, common words in `[names]` get renamed everywhere, including in prose and
  in the agent's own instructions.
- Claude API only.
