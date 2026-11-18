# Research note: micropayments by adding to the vendor's UTXO (KIP-9 mutual transactions, KIP-10 additive addresses)

*Status: research, not implemented. Planned after the public review and the bug bounty, so the reviewed contract does not change during review.*

## Problem

A vault payment creates a new output for the vendor. KIP-9 storage mass grows as `C / amount` for each
output, so a payment below about 0.02 KAS exceeds the network limit of 500,000 g. Confirmed on testnet-10:
a 0.01 TKAS payment was rejected at 1,000,055 g ([journal, L337](../../testnet/journal.md#L337)).

## Idea

KIP-9 already describes the way out: a *mutual* transaction that adds the payment to an existing UTXO of
the vendor instead of creating a new small output. KIP-10 additive addresses let the vendor accept such
additions without signing, as long as the vendor's UTXO only grows (with a minimum increment against spam).
See the research threads:
[Auto-compounding/Additive addresses — KIP10 draft](https://research.kas.pa/t/auto-compounding-additive-addresses-kip10-draft/168)
and [Quadratic storage mass and KIP9](https://research.kas.pa/t/quadratic-storage-mass-and-kip9/159).

## Storage mass, computed with the KIP-9 formula

Vault of 5 KAS (continuation counts as 2 storage units: P2SH plus covenant id), fee 0.015 KAS,
vendor UTXO of 1 KAS.

| Payment | Today: new vendor output | Added to the vendor's 1 KAS UTXO |
|---|---|---|
| 0.001 KAS | 10,000,025 g (rejected) | 3,015 g |
| 0.01 KAS | 1,000,040 g (rejected) | 2,940 g |
| 0.02 KAS | 500,056 g (at the limit) | 2,859 g |

## What the vault would need

- A `pay` path with exactly two inputs: the vault (this covenant) and one vendor additive UTXO, and two
  outputs: the vendor's UTXO grown by exactly `amount`, and the vault continuation.
- Strict input indexing (the vault input and the vendor input at fixed positions), because accepting two
  inputs reopens the class of issue fixed in DeliveryEscrow v0.2 (R26).
- The vendor's script and the increment threshold checked by the vendor's own KIP-10 script, not by ours.

## Open points

- Concurrency on the vendor side: a vendor serving many clients needs a pool of additive UTXOs
  (Michael Sutton's answer in the KIP-9 thread).
- Griefing by repeated tiny additions to a vendor UTXO, mitigated by the minimum increment.
- Compatibility with the x402 profile: the vendor advertises an additive address in the 402 response.
- Payment channels (for example [Kurrent](https://research.kas.pa/t/kurrent-an-eltoo-inspired-latest-state-channel-on-kaspa/494))
  remain an option for long-lived agent–service relationships.
