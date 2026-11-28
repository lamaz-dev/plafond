//! L'adresse de retour d'un coffre : là où l'argent revient quand le propriétaire en reprend une
//! partie ou ferme le coffre. Elle est FIGÉE dans le coffre à sa création : même la clé du
//! propriétaire ne peut pas envoyer l'argent ailleurs. Elle doit donc être juste, et sa clé doit
//! être hors de cet ordinateur.
//!
//!     « L'ordinateur pilote les agents, le téléphone garde l'argent. »
//!
//! Trois situations, trois parcours :
//!  - `Portefeuille` : « J'ai un Ledger ou un portefeuille Kaspa ». L'utilisateur donne son adresse ;
//!    on vérifie sa forme, on la lui remontre découpée pour qu'il la compare sur son appareil, et,
//!    si son portefeuille sait signer un message, on vérifie sa signature.
//!  - `Plateforme` : « J'ai un compte sur une plateforme ». Adresse de dépôt KAS de la plateforme,
//!    saisie deux fois, avec un avertissement explicite : l'adresse est figée.
//!  - `Nouveau` : « Je n'ai rien ». Un portefeuille de retour est créé ICI, sa phrase de secours est
//!    affichée une seule fois, vérifiée par ressaisie, et n'est JAMAIS écrite sur disque ni envoyée
//!    où que ce soit : l'outil ne garde que l'adresse.
//! Plafond ne détient ni ces clés ni ces fonds, et aucun serveur de Plafond ne voit cette phrase.

use kaspa_addresses::{Address, Prefix, Version};
use secp256k1::{Message, XOnlyPublicKey, schnorr::Signature};
use zeroize::Zeroizing;

use crate::Res;

/// Le principe, affiché à la création.
pub const PRINCIPE: &str = "L'ordinateur pilote les agents, le téléphone garde l'argent.";
/// Chemin de dérivation standard de Kaspa (BIP-44, type de monnaie 111111), première adresse de
/// réception. C'est celui des portefeuilles Kaspa courants ; les anciens portefeuilles (KDX,
/// wallet.kaspanet.io) en utilisaient un autre et sont dépréciés.
pub const CHEMIN: &str = crate::cle::CHEMIN_DERIVATION;
/// Réseau de l'outil aujourd'hui : le réseau de test (adresses `kaspatest:`). Sur le réseau
/// principal, ce sera `kaspa:`.
pub const RESEAU: Prefix = Prefix::Testnet;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Profil {
    Portefeuille,
    Plateforme,
    Nouveau,
}

impl Profil {
    pub fn lire(s: &str) -> Res<Profil> {
        match s {
            "portefeuille" => Ok(Profil::Portefeuille),
            "plateforme" => Ok(Profil::Plateforme),
            "nouveau" => Ok(Profil::Nouveau),
            _ => Err("situation inconnue : portefeuille, plateforme ou nouveau".into()),
        }
    }
    pub fn titre(&self) -> &'static str {
        match self {
            Profil::Portefeuille => "J'ai un Ledger ou un portefeuille Kaspa",
            Profil::Plateforme => "J'ai un compte sur une plateforme (Finst, Kraken…)",
            Profil::Nouveau => "Je n'ai rien : créer un portefeuille de retour",
        }
    }
}

/// Avertissement du parcours « plateforme », à afficher en entier avant la double saisie.
pub const AVERTISSEMENT_PLATEFORME: &str = "Cette adresse sera FIGÉE dans le coffre : personne ne pourra la changer, pas même vous. \
Si la plateforme change votre adresse de dépôt, ferme votre compte ou arrête le KAS, ce qui reviendra du coffre pourra être perdu. \
Vérifiez sur la plateforme que cette adresse de dépôt KAS est permanente et à votre nom, et qu'aucun mémo ou étiquette n'est exigé \
(le coffre ne peut pas en joindre). En cas de doute, préférez un portefeuille dont vous gardez la clé.";

/// Résultat du contrôle d'une adresse saisie.
#[derive(Debug, Clone, PartialEq)]
pub struct Controle {
    pub adresse: Address,
    /// L'adresse découpée par groupes, pour la comparer à l'œil avec l'appareil qui la détient.
    pub apercu: String,
    pub avertissements: Vec<String>,
    /// Vrai si une signature de message peut prouver que l'utilisateur détient la clé.
    pub signature_possible: bool,
}

/// Découpe une adresse pour la relecture : préfixe, puis groupes de quatre caractères.
pub fn apercu(a: &Address) -> String {
    let s = a.to_string();
    let (prefixe, corps) = s.split_once(':').unwrap_or(("", s.as_str()));
    let groupes: Vec<String> = corps.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    format!("{prefixe}: {}", groupes.join(" "))
}

/// Contrôle d'une adresse de retour saisie. `confirmation` : la seconde saisie (obligatoire pour une
/// plateforme). `interdites` : adresses qui ne peuvent pas servir de retour (celle de l'agent, celle
/// du coffre) ; `tresorerie` : l'adresse de la clé du propriétaire sur cet ordinateur.
pub fn controler(profil: Profil, saisie: &str, confirmation: Option<&str>, interdites: &[String], tresorerie: Option<&str>) -> Res<Controle> {
    let propre: String = saisie.split_whitespace().collect();
    if propre.is_empty() {
        return Err("adresse de retour manquante".into());
    }
    if propre.starts_with("kaspa:") && RESEAU == Prefix::Testnet {
        return Err("cette adresse est du réseau principal (kaspa:) ; l'outil fonctionne aujourd'hui sur le réseau de test : une adresse kaspatest: est attendue".into());
    }
    if !propre.starts_with(&format!("{RESEAU}:")) {
        return Err(format!("une adresse Kaspa commence par {RESEAU}: (vérifiez que vous n'avez pas collé l'adresse d'une autre monnaie)").into());
    }
    // La somme de contrôle de l'adresse attrape une faute de frappe ou un caractère manquant.
    let adresse = Address::try_from(propre.as_str()).map_err(|_| "adresse invalide : un caractère est faux ou manquant (la somme de contrôle ne correspond pas)")?;
    if adresse.prefix != RESEAU {
        return Err(format!("adresse d'un autre réseau : {RESEAU}: attendu").into());
    }
    if interdites.iter().any(|i| *i == adresse.to_string()) {
        return Err("cette adresse est celle de l'agent ou du coffre lui-même : elle ne peut pas servir d'adresse de retour".into());
    }
    let mut avertissements = vec![];
    if profil == Profil::Plateforme {
        let seconde: String = confirmation.ok_or("saisissez l'adresse une seconde fois pour la confirmer")?.split_whitespace().collect();
        if seconde != propre {
            return Err("les deux saisies de l'adresse ne sont pas identiques : recopiez-la depuis la plateforme".into());
        }
        avertissements.push(AVERTISSEMENT_PLATEFORME.to_string());
    }
    if tresorerie == Some(adresse.to_string().as_str()) {
        avertissements.push("Cette adresse est la trésorerie de cet ordinateur : l'argent repris reviendrait là où se trouve déjà la clé qui pilote les agents. À réserver aux essais.".into());
    }
    match adresse.version {
        Version::PubKey => {}
        Version::PubKeyECDSA => avertissements.push("Adresse de type ECDSA : acceptée ; la vérification par signature de message n'est pas proposée pour ce type.".into()),
        Version::ScriptHash => avertissements.push("Adresse de script (multisignature ou contrat) : assurez-vous de savoir la dépenser ; aucune vérification par signature n'est possible.".into()),
    }
    Ok(Controle { apercu: apercu(&adresse), signature_possible: adresse.version == Version::PubKey && profil == Profil::Portefeuille, adresse, avertissements })
}

/// Le message que l'utilisateur signe dans son portefeuille pour prouver qu'il détient la clé de
/// l'adresse de retour. Il nomme l'usage et l'adresse : la signature ne sert à rien d'autre.
pub fn message_a_signer(adresse: &Address) -> String {
    format!("Plafond : je confirme que {adresse} est mon adresse de retour.")
}

/// Vérifie une signature de message Kaspa (« personal message » : Schnorr sur blake2b-256 à clé
/// « PersonalMessageSigningHash », le format de rusty-kaspa). Seulement pour une adresse à clé
/// Schnorr. `signature` : 64 octets en hexadécimal.
pub fn signature_valide(adresse: &Address, message: &str, signature: &str) -> bool {
    if adresse.version != Version::PubKey {
        return false;
    }
    let (Ok(pk), Some(sig)) = (XOnlyPublicKey::from_slice(&adresse.payload), hex::decode(signature.trim()).ok().and_then(|s| Signature::from_slice(&s).ok())) else {
        return false;
    };
    secp256k1::SECP256K1.verify_schnorr(&sig, &empreinte_message(message), &pk).is_ok()
}

fn empreinte_message(message: &str) -> Message {
    let h = blake2b_simd::Params::new().hash_length(32).key(b"PersonalMessageSigningHash").hash(message.as_bytes());
    Message::from_digest(*h.as_bytes().first_chunk::<32>().expect("32 octets"))
}

/// Un portefeuille de retour tout neuf (parcours « Je n'ai rien »). La phrase n'existe qu'en
/// mémoire, le temps de l'afficher ; elle est effacée dès que cette valeur disparaît.
pub struct Nouveau {
    /// 24 mots BIP-39 (anglais), à noter sur papier puis à importer dans un portefeuille Kaspa.
    pub phrase: Zeroizing<String>,
    /// Première adresse de réception (chemin `CHEMIN`).
    pub adresse: Address,
}

fn adresse_du_coffret(c: &crate::cle::Coffret) -> Res<Address> {
    let k = crate::cle::cle_du_coffret(c)?;
    Ok(Address::new(RESEAU, Version::PubKey, &k.x_only_public_key().0.serialize()))
}

/// Crée le portefeuille de retour : 256 bits d'aléa du système, phrase de 24 mots, première adresse.
/// Rien n'est écrit nulle part.
pub fn generer() -> Res<Nouveau> {
    let c = crate::cle::nouveau_coffret()?;
    Ok(Nouveau { phrase: crate::cle::phrase(&c)?, adresse: adresse_du_coffret(&c)? })
}

/// Adresse de retour correspondant à une phrase saisie (somme de contrôle BIP-39 vérifiée).
pub fn adresse_de_phrase(phrase: &str) -> Res<Address> {
    adresse_du_coffret(&crate::cle::depuis_phrase(phrase)?)
}

/// Vérification par ressaisie : la phrase retapée redonne-t-elle bien l'adresse annoncée ? L'outil
/// n'a donc besoin de garder QUE l'adresse entre l'affichage et la ressaisie, jamais la phrase.
pub fn ressaisie_correcte(attendue: &Address, saisie: &str) -> Res<()> {
    let saisie = Zeroizing::new(saisie.to_string());
    match adresse_de_phrase(&saisie) {
        Ok(a) if a == *attendue => Ok(()),
        Ok(_) => Err("cette phrase est valide, mais ce n'est pas celle qui vient d'être affichée : vérifiez l'ordre des mots".into()),
        Err(e) => Err(format!("phrase non reconnue ({e}) : vérifiez chaque mot sur votre papier").into()),
    }
}

/// Consignes affichées avec la phrase du parcours « Je n'ai rien ».
pub const CONSIGNES_NOUVEAU: &[&str] = &[
    "Notez ces 24 mots sur papier, dans l'ordre. Ils ne seront plus jamais affichés.",
    "Ne les photographiez pas, ne les copiez pas dans un fichier, un courriel ou une messagerie.",
    "Installez un portefeuille Kaspa sur votre téléphone et importez-y ces mots : c'est lui qui gardera l'argent repris du coffre.",
    "Cet ordinateur ne garde que l'adresse. Sans ces mots, l'argent qui reviendra du coffre sera perdu : personne, pas même Plafond, ne peut les retrouver.",
];

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Keypair;

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }
    fn adr(b: u8) -> Address {
        Address::new(RESEAU, Version::PubKey, &k(b).x_only_public_key().0.serialize())
    }

    #[test]
    fn portefeuille_format_prefixe_et_apercu() {
        let a = adr(11);
        let c = controler(Profil::Portefeuille, &format!("  {a} \n"), None, &[], None).unwrap();
        assert_eq!(c.adresse, a);
        assert!(c.signature_possible && c.avertissements.is_empty());
        // L'aperçu contient toute l'adresse, découpée : rien n'est tronqué.
        assert_eq!(c.apercu.replace(' ', ""), a.to_string());
        assert!(c.apercu.starts_with("kaspatest: ") && c.apercu.split(' ').skip(1).all(|g| g.len() <= 4));
        // Une adresse collée avec des espaces (copiée depuis l'aperçu) est acceptée.
        assert_eq!(controler(Profil::Portefeuille, &c.apercu, None, &[], None).unwrap().adresse, a);
        // Fautes : un caractère changé, un caractère manquant, un autre réseau, une autre monnaie, rien.
        let s = a.to_string();
        let faux = format!("{}{}", &s[..s.len() - 1], if s.ends_with('q') { 'p' } else { 'q' });
        assert!(controler(Profil::Portefeuille, &faux, None, &[], None).unwrap_err().to_string().contains("somme de contrôle"));
        assert!(controler(Profil::Portefeuille, &s[..s.len() - 1], None, &[], None).is_err());
        let principal = Address::new(Prefix::Mainnet, Version::PubKey, &a.payload).to_string();
        assert!(controler(Profil::Portefeuille, &principal, None, &[], None).unwrap_err().to_string().contains("réseau principal"));
        assert!(controler(Profil::Portefeuille, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", None, &[], None).unwrap_err().to_string().contains("autre monnaie"));
        assert!(controler(Profil::Portefeuille, "   ", None, &[], None).is_err());
        // L'adresse de l'agent ou du coffre est refusée ; la trésorerie est acceptée avec un avertissement.
        assert!(controler(Profil::Portefeuille, &s, None, &[s.clone()], None).is_err());
        assert_eq!(controler(Profil::Portefeuille, &s, None, &[], Some(&s)).unwrap().avertissements.len(), 1);
    }

    #[test]
    fn plateforme_double_saisie_et_avertissement() {
        let a = adr(12).to_string();
        assert!(controler(Profil::Plateforme, &a, None, &[], None).unwrap_err().to_string().contains("seconde fois"));
        assert!(controler(Profil::Plateforme, &a, Some(&adr(13).to_string()), &[], None).unwrap_err().to_string().contains("pas identiques"));
        let c = controler(Profil::Plateforme, &a, Some(&format!(" {a} ")), &[], None).unwrap();
        assert!(c.avertissements[0].contains("FIGÉE") && c.avertissements[0].contains("perdu") && c.avertissements[0].contains("mémo"));
        assert!(!c.signature_possible, "une plateforme ne signe pas de message");
        // Adresse ECDSA (courante sur les plateformes) : acceptée, avec une note.
        let ecdsa = Address::new(RESEAU, Version::PubKeyECDSA, &k(12).public_key().serialize()).to_string();
        assert_eq!(controler(Profil::Plateforme, &ecdsa, Some(&ecdsa), &[], None).unwrap().avertissements.len(), 2);
    }

    #[test]
    fn signature_de_message_verifiee() {
        let a = adr(11);
        let msg = message_a_signer(&a);
        assert!(msg.contains(&a.to_string()));
        let sig = hex::encode(k(11).sign_schnorr(empreinte_message(&msg)).as_ref());
        assert!(signature_valide(&a, &msg, &sig));
        assert!(signature_valide(&a, &msg, &format!("  {sig}\n")));
        assert!(!signature_valide(&a, &message_a_signer(&adr(12)), &sig), "signature d'un autre message");
        assert!(!signature_valide(&adr(12), &msg, &sig), "signature d'une autre clé");
        assert!(!signature_valide(&a, &msg, "00") && !signature_valide(&a, &msg, "pas de l'hexadécimal"));
        let ecdsa = Address::new(RESEAU, Version::PubKeyECDSA, &k(11).public_key().serialize());
        assert!(!signature_valide(&ecdsa, &msg, &sig));
    }

    /// Le format de l'empreinte est celui de rusty-kaspa : blake2b-256 à clé « PersonalMessageSigningHash »
    /// (kaspa-hashes, `hashers.rs`). Valeur figée pour qu'un changement se voie.
    #[test]
    fn empreinte_de_message_au_format_kaspa() {
        let attendu = blake2b_simd::Params::new().hash_length(32).key(b"PersonalMessageSigningHash").hash(b"Hello Kaspa!");
        assert_eq!(empreinte_message("Hello Kaspa!").as_ref(), attendu.as_bytes());
        assert_ne!(empreinte_message("Hello Kaspa!").as_ref(), blake2b_simd::Params::new().hash_length(32).hash(b"Hello Kaspa!").as_bytes(), "la clé de domaine compte");
    }

    #[test]
    fn nouveau_portefeuille_affiche_une_fois_verifie_par_ressaisie() {
        let n = generer().unwrap();
        let mots: Vec<&str> = n.phrase.split(' ').collect();
        assert_eq!(mots.len(), 24);
        assert_eq!(n.adresse.prefix, RESEAU);
        assert_eq!(n.adresse.version, Version::PubKey);
        // Deux créations : deux portefeuilles différents (aléa du système).
        let autre = generer().unwrap();
        assert_ne!(*n.phrase, *autre.phrase);
        assert_ne!(n.adresse, autre.adresse);
        // Ressaisie : exacte, avec des majuscules ou des espaces en trop : acceptée.
        ressaisie_correcte(&n.adresse, &n.phrase).unwrap();
        ressaisie_correcte(&n.adresse, &format!("  {}  ", n.phrase.to_uppercase().replace(' ', "   "))).unwrap();
        // Deux mots intervertis, un mot manquant, la phrase d'un autre portefeuille : refusées.
        let mut inverses = mots.clone();
        inverses.swap(0, 1);
        assert!(ressaisie_correcte(&n.adresse, &inverses.join(" ")).is_err());
        assert!(ressaisie_correcte(&n.adresse, &mots[..23].join(" ")).is_err());
        assert!(ressaisie_correcte(&n.adresse, &autre.phrase).unwrap_err().to_string().contains("pas celle"));
        assert!(ressaisie_correcte(&n.adresse, "").is_err());
    }

    /// Le portefeuille de retour suit la dérivation standard de Kaspa (BIP-39, BIP-44, type de
    /// monnaie 111111, première adresse de réception) : la phrase importée dans un portefeuille Kaspa
    /// standard redonne la même adresse. Vecteur figé : entropie nulle (phrase « abandon … art »).
    #[test]
    fn derivation_standard_kaspa() {
        assert_eq!(CHEMIN, "m/44'/111111'/0'/0/0");
        let phrase = format!("{}art", "abandon ".repeat(23));
        let a = adresse_de_phrase(&phrase).unwrap();
        // Recalcul indépendant, pas à pas, avec kaspa-bip32 (la bibliothèque des portefeuilles rusty-kaspa).
        let m = kaspa_bip32::Mnemonic::new(phrase.as_str(), kaspa_bip32::Language::English).unwrap();
        let racine = kaspa_bip32::ExtendedPrivateKey::<kaspa_bip32::SecretKey>::new(m.to_seed("").as_bytes()).unwrap();
        let enfant = racine.derive_path(&"m/44'/111111'/0'/0/0".parse::<kaspa_bip32::DerivationPath>().unwrap()).unwrap();
        let cle = Keypair::from_seckey_slice(secp256k1::SECP256K1, &kaspa_bip32::PrivateKey::to_bytes(enfant.private_key())).unwrap();
        assert_eq!(a, Address::new(RESEAU, Version::PubKey, &cle.x_only_public_key().0.serialize()));
        // Le portefeuille de retour n'est PAS dérivé de la clé du propriétaire : c'est une phrase à part.
        assert_ne!(generer().unwrap().adresse, a);
    }
}
