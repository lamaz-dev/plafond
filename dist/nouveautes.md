**What's new in v0.9.2**
- Core v0.9.2 with KIP-20 lineage: the number of vault coins is fixed at creation and can never grow, whatever key is stolen. The loss bound now holds for the whole vault. Tried on testnet-10 on 28 Nov. 2026, real attacks refused by the network (`spec/essai-testnet-2026-11-28-v0.9.2.md`).
- Keyless refill through a deposit address (airlock v0.2.1): anyone can top up an agent's vault, money can only reach the vault or the return address. The deposit address is signed by the owner and can be checked with `vault-cli sas-verifier`.
- Three owner actions: Add, Take back (partial withdrawal, without closing the vault) and Close (final, also returns pending deposits).
- Return address chosen at creation in three guided ways: phone wallet or Ledger (recommended), exchange account, or a backup wallet created on this computer.
- Funding: per-agent funding requests in the gateway, buy and sell links (Finst, Kraken), Send button.
- New vaults use core v0.9.2. Existing v0.7 vaults stay manageable.
