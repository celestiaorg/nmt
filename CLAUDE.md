# CLAUDE.md

## Pull Requests

- Title format: `type(scope)!: [level] subject` (conventional commit), e.g. `fix: [high] correct proof verification`. See [README.md#contributing](README.md#contributing).
- `[high]`: hashing, proof generation/verification, namespace range logic, or other consensus-critical or security-sensitive changes. `[medium]`: other code changes with limited impact. `[low]`: docs, tests, or tooling.
- Use the higher level when unsure. Include the tag in the description with a brief reason, e.g. `Review level: [low] — documentation only.`

## Security PRs

- For PRs that resolve Hacken bug bounty reports, do not include details about the bug in the PR description. Instead, link to a Linear issue that contains more details on the bug and the link to the Hacken bug bounty report.
