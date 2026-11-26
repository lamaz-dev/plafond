# End-to-end demo (test network, no real money)

*English · [Français](DEMO.fr.md)*

**Fastest:** download the ready-to-run package for your system from [Releases](https://github.com/lamaz-dev/plafond/releases/latest), unpack it and run `./demo` (or `Demo.bat`). No Rust needed. To build from source instead:

```
git clone https://github.com/lamaz-dev/plafond.git
cd plafond
./demo.sh
```

Requirements: Git, Rust (https://rustup.rs) and a C compiler (Linux: `build-essential`; macOS: `xcode-select --install`).
The script checks everything before it starts. It asks for no phrase and no password: it creates throwaway test-network keys.
The console opens by itself in your browser. If test coins are missing, the script shows the address, a QR code and the amount, then resumes on its own.
Duration: 5 to 10 minutes, plus the first build.

## What the demo shows (every step is checked)

1. create an agent;
2. give it a budget (2 units per day, at most 0.5 per purchase): its vault opens;
3. give it a secret (an API key encrypted for that agent only);
4. connect it: its key moves to "its server", the console erases its copy;
5. it pays for a service (a demo service we operate);
6. it tries to exceed its budget: **the network rejects it** (not a local check);
7. emergency stop: the vault's funds return to the treasury.

Before touching the network, the script checks offline that the compiled contract is the published one and that it
rejects the overspend. At the end: a summary of the 7 steps and a report `cli/demo-rapport-<date>.json` (links to every
transaction), also written on failure with the cause of the interruption: please attach it to your feedback.

## External dependencies

- **A test-network node**, found automatically, or your own: `NOEUD_WRPC=ws://127.0.0.1:17210 ./demo.sh`.
- **No indexer**: after an agent payment, the console finds the vault again by re-reading the node's chain from a
  marker recorded when the vault was created.
- The test-coin faucet, once. Explorer links are plain read-only links.

## Troubleshooting

- "Rust absent", "compilateur C absent" (Rust or C compiler missing): install what is shown, run `./demo.sh` again.
- "réseau de test injoignable" (test network unreachable after 3 attempts): check your connection, or give a node with `NOEUD_WRPC=ws://…`.
- "la console ne s'est pas ouverte" (console did not open): another console already uses port 8404; close it and run again (nothing was done).
- "fonds non reçus après 20 min" (funds not received after 20 min): faucet unavailable; try later, the address stays the same.
- Step 6 fails (payment accepted): serious anomaly, keep the report and do not run again. Please report it privately ([SECURITY.md](SECURITY.md)).
- Start from scratch: delete `cli/demo-jetable/` (new keys are created, so new test coins are needed).

The script's messages are currently in French; an English version is on the [roadmap](ROADMAP.md).

## Using Plafond with your own account (testnet-10)

The demo above uses throwaway keys. To keep an account:

```
./plafond.sh          # Linux / macOS
Plafond.bat           # Windows, next to vault-cli.exe
```

The console opens locked in your browser. The first time, create your account (a password of 12 characters
or more): your key is generated and encrypted on your computer, in the `compte` folder. There is no email and no
server. The next times, sign in with the password (and the 6-digit code if you enabled two-factor authentication).
Forgot the password? "Restore with my 24-word phrase" recreates the key under a new password; the old file is kept.
Back up your recovery phrase from the banner as soon as the account is created.

### Developer quick start (5 minutes)

1. Run `Plafond.bat` (or `./plafond.sh`): the console opens in your browser. Keep the terminal window open; it runs
   the console.
2. No password: on first launch the console opens in **trial mode** (unprotected test keys, test network only).
   Your **two addresses** show at the top of the page right away:
   - the **main address** (your treasury);
   - a **test return address**: a second wallet created with the account (`compte/retour-test.key`, encrypted). It
     is suggested for every new mandate; freezing sends the money there.
3. "Get free test funds" copies your main address and opens the faucet: paste it and request TKAS. The balance
   shows as soon as they arrive.
4. Create a mandate (the return address is already filled in), then stop it: check on the explorer that the money
   goes to the return address, not to your treasury.

To try the full flow (password, 24 words, two-factor authentication): Settings > Security > "Protect this
account". Addresses, funds and mandates stay the same. To start with a password right away: `set PLAFOND_PROTEGE=1`
(or `PLAFOND_PROTEGE=1 ./plafond.sh`) before the first launch.

The test return address lives on the same computer as your key: it is for trying things out, not for protection. For
real use, set the address of a Ledger, a multisig or a custodian.
