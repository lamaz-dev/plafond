//! Moteur de risque (spec/moteur-de-risque.md) : perte maximale garantie, calculée à partir des
//! paramètres des contrats et de l'état de la chaîne. Lecture seule : ne détient aucun fonds.
//! Test de garantie : `fuzz::depense_reelle_sous_la_perte_maximale_annoncee`.

use crate::VaultParams;
use serde_json::{Value, json};

/// Un couloir AgentBudget tel qu'il est sur la chaîne.
pub struct Couloir {
    pub agent: String,
    pub params: VaultParams,
    /// Score DAA d'inscription du coffre courant (`OpTxInputDaaScore`).
    pub creation: i64,
    pub valeur: u64,
}

/// Fonds déjà sortis d'un couloir et engagés chez un vendeur (séquestre, ardoise).
pub struct Engagement {
    pub agent: String,
    pub vendeur: String,
    pub valeur: u64,
}

impl Couloir {
    /// M1 du couloir : `min(V, A)`, A étant exactement ce que le script accepterait maintenant.
    pub fn immediate(&self, now: i64) -> i64 {
        self.params.available(now, self.creation).clamp(0, self.valeur as i64)
    }

    /// M2 du couloir sur D scores DAA : `min(V, A + C × D / R)` (lemme et théorème de borne-de-perte.md).
    pub fn fenetre(&self, now: i64, d: i64) -> i64 {
        let a = self.params.available(now, self.creation).max(0) as i128;
        let recharge = self.params.capacity as i128 * d.max(0) as i128 / self.params.refill_period.max(1) as i128;
        (a + recharge).min(self.valeur as i128) as i64
    }

    /// Vendeurs payables : `None` = tout vendeur (pas de liste blanche).
    pub fn vendeurs(&self) -> Option<Vec<String>> {
        let zero = hex::encode([0u8; 32]);
        (self.params.use_allowlist != 0).then(|| self.params.payees.iter().filter(|p| **p != zero).cloned().collect())
    }
}

/// Les quatre mesures, au format d'échange de la spec (section 8). Montants en chaînes.
pub fn rapport(couloirs: &[Couloir], engagements: &[Engagement], now: i64, d: i64) -> Value {
    let s = |x: i64| x.to_string();
    let engage: i64 = engagements.iter().map(|e| e.valeur as i64).sum();
    let mut agents: Vec<String> = couloirs.iter().map(|c| c.agent.clone()).chain(engagements.iter().map(|e| e.agent.clone())).collect();
    agents.dedup();
    agents.sort();
    agents.dedup();
    let par_agent: Vec<Value> = agents
        .iter()
        .map(|a| {
            let e: i64 = engagements.iter().filter(|x| &x.agent == a).map(|x| x.valeur as i64).sum();
            let cs = couloirs.iter().filter(|c| &c.agent == a);
            let (m1, m2) = cs.fold((e, e), |(m1, m2), c| (m1 + c.immediate(now), m2 + c.fenetre(now, d)));
            json!({ "agent": a, "immediate": s(m1), "fenetre": s(m2) })
        })
        .collect();
    // Par vendeur : couloirs sans liste blanche → « tout vendeur » ; sinon chaque vendeur listé.
    let mut vendeurs: Vec<(String, i64, bool)> = vec![];
    let mut ajouter = |v: &str, x: i64, restreint: bool| match vendeurs.iter_mut().find(|(n, _, _)| n == v) {
        Some(l) => l.1 += x,
        None => vendeurs.push((v.to_string(), x, restreint)),
    };
    let mut non_couvert = vec![];
    for c in couloirs {
        match c.vendeurs() {
            None => {
                ajouter("*", c.fenetre(now, d), false);
                non_couvert.push(format!("agent:{} sans liste blanche : il peut payer n'importe quel vendeur", c.agent));
            }
            Some(liste) => liste.iter().for_each(|v| ajouter(v, c.fenetre(now, d), true)),
        }
    }
    for e in engagements {
        ajouter(&e.vendeur, e.valeur as i64, true);
    }
    non_couvert.dedup();
    non_couvert.push("fonds hors des coffres Plafond (portefeuille ordinaire d'un agent)".into());
    non_couvert.push("clé du propriétaire compromise".into());
    json!({
        "version": "plafond-risque-v0",
        "daa": s(now),
        "fenetre_daa": s(d),
        "perte_max_immediate_sompi": s(couloirs.iter().map(|c| c.immediate(now)).sum::<i64>() + engage),
        "perte_max_fenetre_sompi": s(couloirs.iter().map(|c| c.fenetre(now, d)).sum::<i64>() + engage),
        "par_agent": par_agent,
        "par_vendeur": vendeurs.iter().map(|(v, x, r)| json!({ "vendeur": v, "fenetre": s(*x), "restreint": r })).collect::<Vec<_>>(),
        "non_couvert": non_couvert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn couloir(agent: &str, tokens: i64, valeur: u64, liste: bool) -> Couloir {
        let k = |b: u8| secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let mut params = VaultParams::ours(&k(1), &k(2), tokens, 1_000);
        params.capacity = 100;
        params.refill_period = 1_000;
        if liste {
            params.use_allowlist = 1;
            params.payees[0] = "aa".repeat(32);
        }
        Couloir { agent: agent.into(), params, creation: 1_000, valeur }
    }

    #[test]
    fn formules_de_la_spec() {
        let c = couloir("a", 40, 10_000, false);
        assert_eq!(c.immediate(1_000), 40); // aucun temps écoulé
        assert_eq!(c.immediate(1_500), 90); // 40 + 500 × 100 / 1000
        assert_eq!(c.immediate(9_999), 100); // plafonné à la capacité
        assert_eq!(c.fenetre(1_500, 2_000), 290); // 90 + 2000 × 100 / 1000
        let petit = couloir("a", 40, 60, false);
        assert_eq!((petit.immediate(1_500), petit.fenetre(1_500, 2_000)), (60, 60)); // jamais plus que le coffre
    }

    #[test]
    fn vendeurs_et_limites_affichees() {
        let r = rapport(
            &[couloir("a", 40, 10_000, false), couloir("b", 40, 10_000, true)],
            &[Engagement { agent: "b".into(), vendeur: "bb".repeat(32), valeur: 7 }],
            1_000,
            1_000,
        );
        assert_eq!(r["perte_max_immediate_sompi"], "87");
        assert_eq!(r["perte_max_fenetre_sompi"], "287");
        let v = r["par_vendeur"].as_array().unwrap();
        assert!(v.iter().any(|x| x["vendeur"] == "*" && x["fenetre"] == "140" && x["restreint"] == false));
        assert!(v.iter().any(|x| x["vendeur"] == "aa".repeat(32) && x["fenetre"] == "140"));
        assert!(r["non_couvert"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("agent:a sans liste blanche")));
        assert_eq!(r["par_agent"].as_array().unwrap().len(), 2);
    }
}
