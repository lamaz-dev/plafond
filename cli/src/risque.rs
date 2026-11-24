//! Moteur de risque (spec/moteur-de-risque.md) : perte maximale garantie, calculée à partir des
//! paramètres des contrats et de l'état de la chaîne. Lecture seule : ne détient aucun fonds.
//! Test de garantie : les fuzzings de `coeur.rs` vérifient `Coeur::fenetre` fenêtre par fenêtre.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Rythme d'un coffre cœur v0.6 : capacité C et période R (tout ce qu'il faut pour borner).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rythme {
    pub capacite: i64,
    pub periode: i64,
}

/// Une pièce d'un coffre, telle qu'elle est sur la chaîne.
pub struct Couloir {
    pub agent: String,
    pub params: Rythme,
    /// Score DAA d'inscription de la pièce (non confirmée : l'instant présent, âge 0, borne sûre).
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
    fn coeur(&self) -> crate::coeur::Coeur {
        crate::coeur::Coeur { owner: vec![], agent: vec![], capacite: self.params.capacite.max(1), periode: self.params.periode.max(1) }
    }
    fn age(&self, now: i64) -> u64 {
        (now - self.creation).max(0) as u64
    }

    /// M1 de la pièce : `min(V, C, C·âge/R)`, exactement ce que le script et le réseau accepteraient.
    pub fn immediate(&self, now: i64) -> i64 {
        self.coeur().immediate(self.valeur, self.age(now)) as i64
    }

    /// M2 de la pièce sur D : `min(V, min(C, C·âge/R) + C·D/R)` (spec/borne-de-perte-v0.6.md, §1).
    pub fn fenetre(&self, now: i64, d: i64) -> i64 {
        self.coeur().fenetre(self.valeur, self.age(now), d.max(0) as u64) as i64
    }

    /// Vendeurs payables : le cœur v0.6 n'a pas de liste blanche (tout vendeur).
    pub fn vendeurs(&self) -> Option<Vec<String>> {
        None
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
            let vie: i64 = e + couloirs.iter().filter(|c| &c.agent == a).map(|c| c.valeur as i64).sum::<i64>();
            json!({ "agent": a, "immediate": s(m1), "fenetre": s(m2), "mandat": s(vie) })
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
        // Sur toute la vie des mandats : le capital alloué (tant que le propriétaire n'en ajoute pas).
        "perte_max_mandats_sompi": s(couloirs.iter().map(|c| c.valeur as i64).sum::<i64>() + engage),
        "par_agent": par_agent,
        "par_vendeur": vendeurs.iter().map(|(v, x, r)| json!({ "vendeur": v, "fenetre": s(*x), "restreint": r })).collect::<Vec<_>>(),
        "non_couvert": non_couvert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn couloir(agent: &str, valeur: u64, creation: i64) -> Couloir {
        Couloir { agent: agent.into(), params: Rythme { capacite: 100, periode: 1_000 }, creation, valeur }
    }

    #[test]
    fn formules_de_la_spec() {
        let c = couloir("a", 10_000, 1_000);
        assert_eq!(c.immediate(1_000), 0); // pièce neuve : rien tout de suite
        assert_eq!(c.immediate(1_500), 50); // 500 × 100 / 1000
        assert_eq!(c.immediate(9_999), 100); // plafonné à la capacité
        assert_eq!(c.fenetre(1_500, 2_000), 250); // 50 + 2000 × 100 / 1000
        assert_eq!(c.fenetre(9_999, 2_000), 300); // 100 + 200
        let petit = couloir("a", 60, 0);
        assert_eq!((petit.immediate(1_500), petit.fenetre(1_500, 2_000)), (60, 60)); // jamais plus que la pièce
    }

    #[test]
    fn vendeurs_et_limites_affichees() {
        let r = rapport(
            &[couloir("a", 10_000, 0), couloir("b", 10_000, 0)],
            &[Engagement { agent: "b".into(), vendeur: "bb".repeat(32), valeur: 7 }],
            1_000,
            1_000,
        );
        assert_eq!(r["perte_max_immediate_sompi"], "207");
        assert_eq!(r["perte_max_fenetre_sompi"], "407");
        assert_eq!(r["perte_max_mandats_sompi"], "20007"); // capital alloué + séquestre ouvert
        let v = r["par_vendeur"].as_array().unwrap();
        assert!(v.iter().any(|x| x["vendeur"] == "*" && x["fenetre"] == "400" && x["restreint"] == false));
        assert!(r["non_couvert"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("agent:a sans liste blanche")));
        assert_eq!(r["par_agent"].as_array().unwrap().len(), 2);
    }
}
