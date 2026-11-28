//! Masse critique : calculs exacts de masse (KIP-9 stockage, calcul, transitoire) sur les
//! transactions réellement construites par l'outil, avec le calculateur du consensus Kaspa.
//!
//! Point clé : la sortie de continuation du coffre porte un script P2SH (35 octets) ET un
//! identifiant de covenant (32 octets). Elle occupe donc 2 « unités de stockage » (pluralité 2)
//! et pèse 4 fois plus qu'une sortie ordinaire dans la formule KIP-9 : C · p² / montant.

use kaspa_consensus_core::config::params::TESTNET_PARAMS;
use kaspa_consensus_core::mass::{MassCalculator, UtxoCell, calc_storage_mass, utxo_plurality};
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry};

/// Option `--forcer-masse` : laisser le réseau trancher au lieu de refuser localement.
pub static FORCER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Masse maximale acceptée par le réseau, mesurée sur le testnet-10 le 18 novembre 2026 (essai 8) :
/// « transaction storage mass of 1000055 is larger than max allowed size of 500000 ».
/// Une transaction de 200 000 g de stockage a été acceptée : l'ancien plafond de 100 000 g ne s'applique plus.
pub const MAX_STANDARD_MASS: u64 = 500_000;
/// Prix minimal exigé par les nœuds pour relayer une transaction, mesuré sur le testnet-10 le
/// 28 novembre 2026 (testnet/journal.md) : 100 sompi par gramme de la plus grande des deux masses
/// « calcul » et « transitoire normalisée » (« transaction has 89040 fees which is under the required
/// amount of 222600 for normalized transient mass 2226 »). La masse de stockage limite la forme de
/// la transaction, elle n'entre pas dans ce minimum.
pub const SOMPI_PAR_GRAMME: u64 = 100;

/// Frais minimaux de relais d'une transaction (voir `SOMPI_PAR_GRAMME`). La masse transitoire est
/// ramenée à l'échelle de la masse de calcul par le cofacteur du réseau (0,5 sur testnet-10).
pub fn frais_relais(tx: &Transaction) -> u64 {
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let nc = calc.calc_non_contextual_masses(tx);
    nc.normalized_max(&TESTNET_PARAMS.block_mass_cofactors()) * SOMPI_PAR_GRAMME
}

/// Paramètre C de KIP-9 (1 KAS × 10 000).
pub const STORM: u64 = kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;

pub struct Masses {
    pub compute: u64,
    pub transient: u64,
    pub storage: u64,
}

impl Masses {
    pub fn standard(&self) -> bool {
        self.compute <= MAX_STANDARD_MASS && self.transient <= MAX_STANDARD_MASS && self.storage <= MAX_STANDARD_MASS
    }
}

pub fn masses(tx: &Transaction, entries: &[UtxoEntry]) -> Option<Masses> {
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let nc = calc.calc_non_contextual_masses(tx);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let storage = calc.calc_contextual_masses(&populated)?.storage_mass;
    Some(Masses { compute: nc.compute_mass, transient: nc.transient_mass, storage })
}

/// Masse de stockage d'un paiement du coffre : 1 entrée coffre → [paiement, continuation].
/// `payee_plurality` = 1 pour une adresse ordinaire ou un séquestre sans covenant.
pub fn pay_storage_mass(vault_value: u64, amount: u64, rest: u64, payee_plurality: u64) -> Option<u64> {
    let vault_p = utxo_plurality(&crate::masse::p2sh_like(), true);
    calc_storage_mass(
        false,
        [UtxoCell::new(vault_p, vault_value)].into_iter(),
        [UtxoCell::new(payee_plurality, amount), UtxoCell::new(vault_p, rest)].into_iter(),
        STORM,
    )
}

fn p2sh_like() -> kaspa_consensus_core::tx::ScriptPublicKey {
    kaspa_txscript::pay_to_script_hash_script(&[0u8; 1])
}

/// Plus petit paiement possible (sompi) depuis un coffre de valeur `vault_value`, frais `fee`.
pub fn min_payment(vault_value: u64, fee: u64) -> Option<u64> {
    let ok = |a: u64| a + fee < vault_value && pay_storage_mass(vault_value, a, vault_value - a - fee, 1).is_some_and(|m| m <= MAX_STANDARD_MASS);
    // La masse C·(1/a + 4/reste − 4/v) est minimale vers a ≈ (v − frais)/3 : si ce point échoue,
    // aucun paiement n'est possible ; sinon on cherche le plus petit montant à gauche de ce point.
    let best = vault_value.checked_sub(fee)? / 3;
    if best == 0 || !ok(best) {
        return None;
    }
    let (mut lo, mut hi) = (1u64, best);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if ok(mid) { hi = mid } else { lo = mid + 1 }
    }
    Some(lo)
}

/// Plus petit solde de coffre qui permet encore au moins un paiement (plancher de survie du couloir).
pub fn survival_floor(fee: u64) -> u64 {
    let (mut lo, mut hi) = (fee + 2, 100 * 100_000_000u64);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if min_payment(mid, fee).is_some() { hi = mid } else { lo = mid + 1 }
    }
    lo
}

/// Rapport lisible pour la commande `masse`.
pub fn rapport(fee: u64) -> String {
    let kas = |s: u64| s as f64 / 1e8;
    let mut r = String::new();
    r.push_str(&format!("Plancher de survie d'un couloir (frais {} TKAS) : {:.4} TKAS\n", kas(fee), kas(survival_floor(fee))));
    r.push_str("Solde du coffre -> plus petit paiement possible :\n");
    for v in [50_000_000u64, 60_000_000, 100_000_000, 200_000_000, 500_000_000, 1_000_000_000, 10_000_000_000] {
        match min_payment(v, fee) {
            Some(a) => r.push_str(&format!("  {:>7.2} TKAS -> {:.4} TKAS\n", kas(v), kas(a))),
            None => r.push_str(&format!("  {:>7.2} TKAS -> aucun paiement possible (couloir bloqué)\n", kas(v))),
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn keys() -> (secp256k1::Keypair, secp256k1::Keypair) {
        let k = |b: u8| secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        (k(1), k(2))
    }

    fn etat(valeur: u64, tokens: i64, owner: &secp256k1::Keypair, agent: &secp256k1::Keypair) -> (Etat, UtxoEntry) {
        let e = Etat { txid: "11".repeat(32), index: 0, valeur, tokens, last_daa: 1_000, cov_id: "22".repeat(32) };
        let p = VaultParams::ours(owner, agent, tokens, 1_000);
        let entry = UtxoEntry::new(valeur, vault_spk(&compile_params(&p).unwrap()), 0, false, Some(e.covenant().unwrap()));
        (e, entry)
    }

    #[test]
    fn la_continuation_du_coffre_pese_double() {
        let (o, a) = keys();
        let (e, _) = etat(FUND, CAPACITY, &o, &a);
        let p = VaultParams::ours(&o, &a, e.tokens, e.last_daa);
        let spk = vault_spk(&compile_params(&p).unwrap());
        assert_eq!(utxo_plurality(&spk, true), 2, "P2SH + identifiant de covenant = 2 unités");
        assert_eq!(utxo_plurality(&spk, false), 1);
    }

    #[test]
    fn masses_d_un_paiement_reel_sous_le_plafond() {
        // Coffre complet tel que déployé (liste blanche de 3 adresses comprise) : paiement de 0,2 TKAS.
        let (o, a) = keys();
        let (e, entry) = etat(FUND, CAPACITY, &o, &a);
        let (tx, _) = build_pay(&o, &a, &e, 20_000_000, pay_to_address_script(&address(&payee(&o))), 2_000, e.last_daa).unwrap();
        let m = masses(&tx, &[entry]).unwrap();
        eprintln!("calcul {} g, transitoire {} g, stockage {} g", m.compute, m.transient, m.storage);
        assert!(m.compute < 20_000, "masse de calcul trop élevée : {}", m.compute);
        assert!(m.transient < 20_000, "masse transitoire trop élevée : {}", m.transient);
        assert!(m.standard());
        // les frais exigés (100 sompi/g sur la masse de calcul) tiennent dans FEE et MAX_FEE
        assert!(m.compute * 100 <= FEE && FEE <= MAX_FEE as u64);
    }

    #[test]
    fn micro_paiement_refuse_par_kip9() {
        // 0,001 TKAS : la sortie de paiement seule pèse C / 100 000 = 10 000 000 g, 100 fois le plafond.
        // L'outil refuse avant de signer, avec un message clair.
        let (o, a) = keys();
        let (e, _) = etat(FUND, CAPACITY, &o, &a);
        let r = build_pay(&o, &a, &e, 100_000, pay_to_address_script(&address(&payee(&o))), 2_000, e.last_daa);
        let msg = r.err().expect("doit être refusé").to_string();
        eprintln!("{msg}");
        assert!(msg.contains("KIP-9"));
    }

    #[test]
    fn couloir_presque_vide_bloque() {
        // Scénario de la revue : il reste 0,04 TKAS, l'agent veut payer 0,001 TKAS.
        assert!(pay_storage_mass(4_000_000, 100_000, 4_000_000 - 100_000 - FEE, 1).unwrap() > MAX_STANDARD_MASS);
        assert_eq!(min_payment(4_000_000, FEE), None);
    }

    #[test]
    fn calcul_identique_au_reseau() {
        // Essai 8 sur testnet-10 : coffre de 4,305 TKAS, paiement de 0,01 TKAS refusé par le réseau avec
        // « transaction storage mass of 1000055 ». Notre calcul doit donner exactement ce chiffre.
        let v = 430_500_000u64;
        let m = pay_storage_mass(v, 1_000_000, v - 1_000_000 - FEE, 1).unwrap();
        eprintln!("masse calculée {m} g (réseau : 1000055 g)");
        assert_eq!(m, 1_000_055);
    }

    #[test]
    fn plancher_de_survie() {
        let f = survival_floor(FEE);
        eprintln!("{}", rapport(FEE));
        // Plafond réseau 500 000 g : paiement ≥ ~0,02 TKAS et continuation (pluralité 2) ≥ ~0,08 TKAS.
        assert!(f > 10_000_000 && f < 15_000_000, "plancher inattendu : {f}");
        assert!(min_payment(f, FEE).is_some());
        assert!(min_payment(f - 1, FEE).is_none());
    }

    #[test]
    fn proprietaire_recupere_un_couloir_presque_vide() {
        // Couloir à 0,04 TKAS : le propriétaire ajoute une entrée à lui (1 TKAS) et vide tout vers une sortie.
        // |O| = 1 : formule assouplie, la masse de stockage devient faible.
        let m = calc_storage_mass(
            false,
            [UtxoCell::new(2, 4_000_000), UtxoCell::new(1, 100_000_000)].into_iter(),
            [UtxoCell::new(1, 104_000_000 - FEE)].into_iter(),
            STORM,
        )
        .unwrap();
        eprintln!("récupération avec entrée d'appoint : stockage {m} g");
        assert!(m <= MAX_STANDARD_MASS);
    }

    #[test]
    fn sortie_vers_sequestre_sans_covenant() {
        // Le séquestre DeliveryEscrow est un P2SH sans identifiant de covenant : pluralité 1.
        let spk = kaspa_txscript::pay_to_script_hash_script(&[0u8; 235]);
        assert_eq!(utxo_plurality(&spk, false), 1);
    }
}

/// Exécute l'entrée 0 avec le vrai moteur, sous la limite d'unités de script que le réseau accorde
/// au budget de calcul DÉCLARÉ par l'entrée (consensus : `ComputeCommit::allowed_script_units`).
/// Renvoie les unités de script consommées, ou l'erreur du moteur (dont le dépassement de budget).
#[cfg(test)]
pub fn unites_sous_la_limite_du_reseau(tx: &Transaction, utxos: Vec<UtxoEntry>) -> Result<u64, String> {
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::VerifiableTransaction;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext};
    let populated = PopulatedTransaction::new(tx, utxos);
    let cov = CovenantsContext::from_tx(&populated).map_err(|e| format!("{e:?}"))?;
    let cache = Cache::new(10);
    let reused = SigHashReusedValuesUnsync::new();
    let input = populated.inputs()[0].clone();
    let limite = input.compute_commit.allowed_script_units();
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        &input,
        0,
        populated.utxo(0).unwrap(),
        EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov),
        EngineFlags::default(),
        limite,
    );
    vm.execute().map_err(|e| format!("{e:?}"))?;
    Ok(vm.used_script_units().0)
}
