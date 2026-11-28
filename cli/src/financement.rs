//! Demande de financement : combien d'argent faut-il envoyer, où, pour que l'agent retrouve son budget
//! de requêtes. Plafond ne détient jamais les fonds : il calcule et réclame, le client paie avec ses
//! propres outils (carte via un service d'achat régulé, conservateur, portefeuille), vers une adresse
//! qui ne mène qu'au coffre de l'agent ou au client lui-même.
//!
//! Tout est exprimé en requêtes et dans la devise du client ; l'unité du réseau n'apparaît que dans les
//! champs techniques (`*_sompi`), pour les outils.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

/// Cours indicatifs du KAS dans plusieurs unités de lecture, mis en cache 5 minutes ; absents si
/// l'API ne répond pas. USDT, USDC, BTC, ETH et SOL sont calculés à partir de leur propre cours en
/// dollars (aucune parité supposée).
pub(crate) struct Cours {
    pub(crate) valeur: Option<Value>,
    pub(crate) lu: Option<Instant>,
}

impl Cours {
    pub(crate) fn nouveau() -> Self {
        Cours { valeur: None, lu: None }
    }

    pub(crate) fn lire(&mut self) -> Option<Value> {
        if self.lu.is_some_and(|t| t.elapsed() < Duration::from_secs(300)) {
            return self.valeur.clone();
        }
        self.lu = Some(Instant::now());
        let v = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()
            .get("https://api.coingecko.com/api/v3/simple/price?ids=kaspa,tether,usd-coin,bitcoin,ethereum,solana&vs_currencies=usd,eur,jpy,gbp")
            .call()
            .ok()
            .and_then(|r| r.into_string().ok())
            .and_then(|t| serde_json::from_str::<Value>(&t).ok());
        self.valeur = v.and_then(|v| {
            let usd = |id: &str| v[id]["usd"].as_f64().filter(|x| *x > 0.0);
            let kas = usd("kaspa")?;
            let mut c = json!({ "usd": kas, "eur": v["kaspa"]["eur"].as_f64()?, "source": "CoinGecko (indicatif)" });
            for f in ["jpy", "gbp"] {
                if let Some(x) = v["kaspa"][f].as_f64() {
                    c[f] = json!(x);
                }
            }
            for (cle, id) in [("usdt", "tether"), ("usdc", "usd-coin"), ("btc", "bitcoin"), ("eth", "ethereum"), ("sol", "solana")] {
                if let Some(x) = usd(id) {
                    c[cle] = json!(kas / x);
                }
            }
            Some(c)
        });
        self.valeur.clone()
    }
}

/// Réglages de rechargement d'un agent (dans la configuration de la passerelle, clé « recharge »).
#[derive(Deserialize, Clone, Debug)]
pub struct Reglage {
    /// Requêtes visées après un rechargement.
    pub requetes_cible: u64,
    /// En dessous de ce nombre de requêtes, l'agent est signalé (et le webhook prévenu).
    pub seuil_requetes: u64,
    /// Coût d'une requête, frais compris, en sompi (par défaut le tarif de référence de la console).
    pub tarif_requete_sompi: Option<u64>,
    /// Devise d'affichage : eur, usd, gbp, jpy, usdc, usdt…
    #[serde(default = "devise_defaut")]
    pub devise: String,
    /// Adresse où envoyer les fonds. Par défaut : l'adresse du propriétaire, qui recharge le coffre
    /// depuis sa console. Avec le sas de rechargement, ce sera l'adresse du sas de l'agent.
    pub adresse_depot: Option<String>,
}

fn devise_defaut() -> String {
    "eur".into()
}

/// Marge ajoutée au montant en devise : frais du service d'achat et variation du cours pendant le
/// paiement. Le surplus reste au client (il recharge simplement un peu plus de requêtes).
pub const MARGE_POURCENT: f64 = 3.0;

pub const TARIF_REFERENCE_SOMPI: u64 = 40_000_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Besoin {
    pub requetes_restantes: u64,
    pub requetes_cible: u64,
    pub sous_seuil: bool,
    pub manque_sompi: u64,
    /// Montant à payer dans la devise du client (marge comprise), si le cours est connu.
    pub montant: Option<f64>,
}

/// Le calcul lui-même, sans réseau.
pub fn calculer(valeur_sompi: u64, r: &Reglage, cours_devise: Option<f64>) -> Besoin {
    let tarif = r.tarif_requete_sompi.filter(|t| *t > 0).unwrap_or(TARIF_REFERENCE_SOMPI);
    let restantes = valeur_sompi / tarif;
    let manque = r.requetes_cible.saturating_mul(tarif).saturating_sub(valeur_sompi);
    let montant = cours_devise
        .filter(|c| c.is_finite() && *c > 0.0)
        .map(|c| (manque as f64 / 1e8) * c * (1.0 + MARGE_POURCENT / 100.0))
        .map(|m| (m * 100.0).ceil() / 100.0);
    Besoin { requetes_restantes: restantes, requetes_cible: r.requetes_cible, sous_seuil: restantes < r.seuil_requetes, manque_sompi: manque, montant }
}

/// Lien vers un service d'achat, à partir d'un modèle de la configuration
/// (`{adresse}`, `{montant}`, `{devise}`) ; les valeurs sont encodées pour l'URL.
pub fn lien_achat(modele: &str, adresse: &str, montant: f64, devise: &str) -> Option<String> {
    if !modele.starts_with("https://") {
        return None;
    }
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    Some(modele.replace("{adresse}", &enc(adresse)).replace("{montant}", &format!("{montant:.2}")).replace("{devise}", &enc(&devise.to_ascii_uppercase())))
}

/// Une plateforme régulée où le client achète ou revend lui-même ses KAS. Plafond n'y détient rien,
/// n'exécute aucun ordre et ne met pas ses utilisateurs en relation : ce ne sont que des liens.
pub struct Plateforme {
    pub nom: &'static str,
    /// « principal » ou « secours ».
    pub role: &'static str,
    pub lien: &'static str,
    pub acheter: bool,
    pub revendre: bool,
    /// Ce que l'on sait de son statut, avec la source à vérifier par le client.
    pub statut: &'static str,
    /// Vrai si Plafond touche quelque chose quand le client passe par ce lien. Aucun lien ne l'est
    /// aujourd'hui ; s'il le devenait, `MENTION_REMUNERE` s'affiche à côté du lien.
    pub remunere: bool,
}

pub const MENTION_REMUNERE: &str = "Partenariat rémunéré";

/// Liens proposés (choix du propriétaire du projet, 27 nov. 2026). Statuts relevés le 28 nov. 2026
/// sur les sites des autorités et des plateformes ; la disponibilité du KAS et les moyens de
/// paiement se vérifient sur la plateforme elle-même.
pub const PLATEFORMES: &[Plateforme] = &[
    Plateforme {
        nom: "Finst",
        role: "principal",
        lien: "https://finst.com/fr",
        acheter: true,
        revendre: true,
        statut: "Prestataire agréé MiCA par l'AFM (Pays-Bas), inscrit sur la liste blanche de l'AMF. À vérifier sur amf-france.org.",
        remunere: false,
    },
    Plateforme {
        nom: "Kraken",
        role: "secours",
        lien: "https://www.kraken.com/fr",
        acheter: true,
        revendre: true,
        statut: "Licence MiCA délivrée par la Banque centrale d'Irlande. À vérifier sur centralbank.ie.",
        remunere: false,
    },
];

/// Les liens, tels que la console et la passerelle les donnent. Pas d'espace d'échange entre
/// utilisateurs : acheter et revendre se font sur une plateforme régulée, au nom du client.
pub fn liens() -> Value {
    json!({
        "plateformes": PLATEFORMES.iter().map(|p| json!({
            "nom": p.nom, "role": p.role, "lien": p.lien, "acheter": p.acheter, "revendre": p.revendre, "statut": p.statut,
            "partenariat_remunere": p.remunere, "mention": if p.remunere { Some(MENTION_REMUNERE) } else { None },
        })).collect::<Vec<_>>(),
        "principe": "Plafond ne vend pas, n'achète pas et ne met pas ses utilisateurs en relation. Vous achetez ou revendez vous-même, sur une plateforme régulée, à votre nom.",
    })
}

/// Fiche d'un agent pour la demande de financement (JSON de la passerelle et du webhook).
pub fn fiche(nom: &str, b: &Besoin, r: &Reglage, adresse: &str, modele_lien: Option<&str>) -> Value {
    let lien = match (modele_lien, b.montant) {
        (Some(m), Some(montant)) if b.manque_sompi > 0 => lien_achat(m, adresse, montant, &r.devise),
        _ => None,
    };
    json!({
        "agent": nom,
        "requetes_restantes": b.requetes_restantes,
        "requetes_cible": b.requetes_cible,
        "a_recharger": b.sous_seuil,
        "montant": b.montant.map(|m| json!({ "valeur": m, "devise": r.devise.to_ascii_uppercase(), "marge_incluse_pourcent": MARGE_POURCENT })),
        "adresse_depot": adresse,
        "lien_achat": lien,
        "manque_sompi": b.manque_sompi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reglage() -> Reglage {
        Reglage { requetes_cible: 1000, seuil_requetes: 200, tarif_requete_sompi: Some(20_000_000), devise: "eur".into(), adresse_depot: None }
    }

    #[test]
    fn besoin_en_requetes_et_en_devise() {
        // 150 requêtes restantes à 0,2 : sous le seuil, il manque 850 requêtes = 170 unités
        let b = calculer(150 * 20_000_000 + 7, &reglage(), Some(0.03));
        assert_eq!(b.requetes_restantes, 150);
        assert!(b.sous_seuil);
        assert_eq!(b.manque_sompi, 1000 * 20_000_000 - (150 * 20_000_000 + 7));
        // 170 unités × 0,03 € × 1,03 = 5,253 € → 5,26 € (arrondi au centime supérieur)
        assert_eq!(b.montant, Some(5.26));
    }

    #[test]
    fn rien_a_payer_au_dessus_de_la_cible() {
        let b = calculer(2000 * 20_000_000, &reglage(), Some(0.03));
        assert_eq!((b.sous_seuil, b.manque_sompi, b.montant), (false, 0, Some(0.0)));
        assert_eq!(fiche("a", &b, &reglage(), "kaspatest:q", Some("https://achat.exemple/?a={adresse}")).get("lien_achat"), Some(&Value::Null));
    }

    #[test]
    fn cours_inconnu_ou_absurde_pas_de_montant() {
        assert_eq!(calculer(0, &reglage(), None).montant, None);
        assert_eq!(calculer(0, &reglage(), Some(f64::NAN)).montant, None);
        assert_eq!(calculer(0, &reglage(), Some(-1.0)).montant, None);
    }

    #[test]
    fn lien_d_achat_encode_et_https_seulement() {
        let l = lien_achat("https://achat.exemple/buy?to={adresse}&amount={montant}&fiat={devise}", "kaspatest:qq1&x=y", 5.256, "eur").unwrap();
        assert_eq!(l, "https://achat.exemple/buy?to=kaspatest:qq1%26x%3Dy&amount=5.26&fiat=EUR");
        assert_eq!(lien_achat("http://achat.exemple/?a={adresse}", "a", 1.0, "eur"), None);
        assert_eq!(lien_achat("javascript:alert(1)", "a", 1.0, "eur"), None);
    }

    /// Liens externes : https seulement, un principal et un secours, et la mention « partenariat
    /// rémunéré » dès qu'un lien le devient (aucun aujourd'hui).
    #[test]
    fn liens_externes_et_mention_de_remuneration() {
        assert!(PLATEFORMES.iter().all(|p| p.lien.starts_with("https://") && !p.lien.contains('?') && !p.statut.is_empty()), "liens simples, sans paramètre de suivi");
        assert_eq!(PLATEFORMES.iter().filter(|p| p.role == "principal").map(|p| p.nom).collect::<Vec<_>>(), vec!["Finst"]);
        assert!(PLATEFORMES.iter().any(|p| p.role == "secours" && p.nom == "Kraken"));
        assert!(PLATEFORMES.iter().find(|p| p.nom == "Finst").is_some_and(|p| p.acheter && p.revendre));
        let v = liens();
        for (p, j) in PLATEFORMES.iter().zip(v["plateformes"].as_array().unwrap()) {
            assert_eq!(j["partenariat_remunere"], p.remunere);
            assert_eq!(j["mention"].as_str(), p.remunere.then_some(MENTION_REMUNERE), "la mention suit la rémunération");
        }
        assert!(PLATEFORMES.iter().all(|p| !p.remunere), "aucun lien rémunéré aujourd'hui");
        assert!(v["principe"].as_str().unwrap().contains("ne met pas ses utilisateurs en relation"));
    }

    #[test]
    fn tarif_par_defaut_et_tarif_nul() {
        let mut r = reglage();
        r.tarif_requete_sompi = Some(0);
        assert_eq!(calculer(TARIF_REFERENCE_SOMPI * 3, &r, None).requetes_restantes, 3);
    }
}
