# Contributing

Thank you for looking at kaspa-agent-vault. The project is an unaudited prototype under public review,
so the most valuable contributions are reviews and attempts to break it on testnet-10.

## Security issues

Never open a public issue for a vulnerability. Use the private channel described in [`SECURITY.md`](SECURITY.md).

## Bugs, questions, proposals

Open an issue with:
- what you expected and what happened;
- the commit hash, and the testnet-10 transaction id if relevant;
- the smallest reproduction you can give (a failing test is ideal).

## Pull requests

- Every change to a contract (`contracts/*.sil`) needs a test showing the behaviour, and an update of
  `contracts/EMPREINTES.txt` (`vault-cli empreintes > contracts/EMPREINTES.txt`).
- New risks go into `spec/threat-model.md`, new invariants into `spec/invariants.md`.
- The CI must stay green: tests, fuzzing, fingerprints, secret scan.
- Documentation is written in French and English; code comments are in French. English contributions are welcome.

By contributing, you agree that your contribution is licensed under the ISC license of this repository.
