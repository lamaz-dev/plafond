**What's new in v0.8.1**
- Core v0.7 return address: with the owner key, vault funds can only go back to the vault or to a return address fixed when the mandate is created (e.g. a Ledger or a multisig). Default: the treasury. Older v0.6 vaults stay freezable.
- Trial mode: on first launch the console opens with no password and shows two addresses at once (treasury and a test return address, prefilled in every new mandate). "Protect this account" switches to the full flow (password, 24 words, two-factor) with the same addresses.
- Agent keys kept by the console are encrypted with a key derived from the owner key, so restoring from the 24 words keeps your agents.
- Testnet race tests (agent payment vs freeze, vs refill) and a targeted review of the kaspa-x402 relay; findings and fixes in `spec/red-team/`.
