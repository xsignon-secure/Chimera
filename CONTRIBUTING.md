# Contributing to Chimera

Thanks for helping. Issues, ideas and pull requests are all welcome.

## Set up

```bash
git clone https://github.com/xsignon-secure/Chimera && cd Chimera
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

```bash
pytest
ruff check src tests && ruff format --check src tests
mypy src
bandit -ll -r src
shellcheck install.sh deploy/**/*.sh
```

CI runs the same checks, plus a container build and smoke test.

## Ground rules

- **Never add code execution.** No `subprocess`, `eval`, `exec`, `pickle` or shell-outs in the decoy. A test enforces this.
- **Never fetch attacker-supplied URLs** or add outbound network paths from the honeypot container.
- **Every secret stays synthetic.** New fake data must use RFC 1918 addresses and canary-generated values.
- New decoy tools need a test that shows they log the call and stay consistent with the fake world.
- Keep pull requests focused, and describe what you tested.

Security issues go through [SECURITY.md](SECURITY.md), not public issues.

By contributing you agree that your contributions are licensed under the [Apache-2.0](LICENSE) license.
