use pnet::datalink::Channel::Ethernet;
use serde_derive::{Deserialize, Serialize};
use pnet::datalink::{self};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use dialoguer::{theme::ColorfulTheme, Select, Input};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use pnet::packet::ipv4::Ipv4Packet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, io, thread};
use std::path::Path;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Regle {
    id: String,
    protocole: String,
    ip_source: Option<String>,
    ip_destination: Option<String>,
    port_source: Option<u16>,
    port_destination: Option<u16>,
    action: String, // "allow" ou "block"
}

lazy_static! {
    static ref REGLES: Arc<Mutex<Vec<Regle>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static! {
    static ref PAREFEU_EN_COURS: AtomicBool = AtomicBool::new(false);
}

const FICHIER_REGLES: &str = "regles_parefeu.json";

fn sauvegarder_regles(regles: &Vec<Regle>) -> io::Result<()> {
    let json = serde_json::to_string(regles)?;
    fs::write(FICHIER_REGLES, json)?;
    Ok(())
}

fn charger_regles() -> io::Result<Vec<Regle>> {
    let chemin = Path::new(FICHIER_REGLES);
    if chemin.exists() {
        let mut fichier = File::open(chemin)?;
        let mut contenu = String::new();
        fichier.read_to_string(&mut contenu)?;
        let regles = serde_json::from_str(&contenu)?;
        Ok(regles)
    } else {
        Ok(Vec::new())  // Retourne un vecteur vide si le fichier n'existe pas
    }
}

fn main() {
    let regles_chargees = charger_regles().unwrap_or_else(|e| {
        eprintln!("Echec du chargement des regles: {}", e);
        Vec::new()
    });

    *REGLES.lock().unwrap() = regles_chargees;

    loop {
        afficher_menu();
    }
}

fn demarrer_parefeu() {
    let interfaces = datalink::interfaces();
    let noms_interfaces: Vec<String> = interfaces.iter()
        .map(|iface| iface.name.clone())
        .collect();

    if noms_interfaces.is_empty() {
        println!("Aucune interface reseau disponible trouvee.");
        return;
    }

    // Nettoie les logs lors du demarrage du pare-feu
    nettoyer_logs();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Selectionnez une interface reseau a surveiller")
        .default(0)
        .items(&noms_interfaces)
        .interact()
        .unwrap();

    let interface_selectionnee = noms_interfaces.get(selection).unwrap().clone();
    println!("Demarrage du pare-feu sur l'interface: {}", interface_selectionnee);

    PAREFEU_EN_COURS.store(true, Ordering::SeqCst);
    thread::spawn(move || {
        traiter_paquets(interface_selectionnee);
    });
}

fn nettoyer_logs() {
    match File::create("parefeu.log") {
        Ok(_) => println!("Les logs ont ete nettoyes."),
        Err(e) => eprintln!("Echec du nettoyage des logs: {}", e),
    }
}

fn arreter_parefeu() {
    PAREFEU_EN_COURS.store(false, Ordering::SeqCst);
    println!("Pare-feu arrete.");
}

fn verifier_etat_parefeu() {
    if PAREFEU_EN_COURS.load(Ordering::SeqCst) {
        println!("Etat du pare-feu: En cours");
    } else {
        println!("Etat du pare-feu: Arrete");
    }
}

fn afficher_menu() {
    let elements = vec![
        "Voir les Regles", "Ajouter une Regle", "Supprimer une Regle", "Voir les Logs", "Nettoyer les Logs",
        "Demarrer le Pare-feu", "Arreter le Pare-feu", "Verifier l'Etat du Pare-feu",
        "Quitter"
    ];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choisissez une action")
        .default(0)
        .items(&elements)
        .interact()
        .unwrap();

    match elements[selection] {
        "Voir les Regles" => voir_regles(),
        "Ajouter une Regle" => ajouter_regle(),
        "Supprimer une Regle" => supprimer_regle(),
        "Voir les Logs" => voir_logs(),
        "Nettoyer les Logs" => nettoyer_logs(),
        "Demarrer le Pare-feu" => demarrer_parefeu(),
        "Arreter le Pare-feu" => arreter_parefeu(),
        "Verifier l'Etat du Pare-feu" => verifier_etat_parefeu(),
        "Quitter" => std::process::exit(0),
        _ => (),
    }
}

fn voir_regles() {
    let regles = REGLES.lock().unwrap();
    for (index, regle) in regles.iter().enumerate() {
        println!("{}: {:?}", index, regle);
    }
}

fn ajouter_regle() {
    let protocole: String = Input::new()
        .with_prompt("Entrez le protocole (par exemple, 'tcp', 'udp')")
        .interact_text()
        .unwrap();

    let ip_source: String = Input::new()
        .with_prompt("Entrez l'IP source (laissez vide si non applicable)")
        .default("".into())
        .interact_text()
        .unwrap();

    let ip_destination: String = Input::new()
        .with_prompt("Entrez l'IP de destination (laissez vide si non applicable)")
        .default("".into())
        .interact_text()
        .unwrap();

    let port_source: u16 = Input::new()
        .with_prompt("Entrez le port source (laissez vide si non applicable)")
        .default(0)
        .interact_text()
        .unwrap();

    let port_destination: u16 = Input::new()
        .with_prompt("Entrez le port de destination (laissez vide si non applicable)")
        .default(0)
        .interact_text()
        .unwrap();

    let actions = vec!["Autoriser", "Bloquer"];
    let action = Select::new()
        .with_prompt("Choisissez l'action")
        .default(0)
        .items(&actions)
        .interact()
        .unwrap();

    let nouvelle_regle = Regle {
        id: Uuid::new_v4().to_string(),
        protocole,
        ip_source: if ip_source.is_empty() { None } else { Some(ip_source) },
        ip_destination: if ip_destination.is_empty() { None } else { Some(ip_destination) },
        port_source: if port_source == 0 { None } else { Some(port_source) },
        port_destination: if port_destination == 0 { None } else { Some(port_destination) },
        action: actions[action].to_lowercase(),
    };

    let mut regles = REGLES.lock().unwrap();

    regles.push(nouvelle_regle.clone());

    sauvegarder_regles(&regles).expect("Echec de la sauvegarde des regles");

    // IMPORTANT: Mettre a jour les iptables de Linux
    mettre_a_jour_iptables(&nouvelle_regle.clone(), &nouvelle_regle.clone().action);

    println!("Regle ajoutee.");
}

fn mettre_a_jour_iptables(regle: &Regle, action: &str) {
    let protocole = &regle.protocole;
    let ip_source = regle.ip_source.as_ref().map_or("".to_string(), |ip| format!("--source {}", ip));
    let ip_destination = regle.ip_destination.as_ref().map_or("".to_string(), |ip| format!("--destination {}", ip));
    let port_source = regle.port_source.map_or("".to_string(), |port| format!("--sport {}", port));
    let port_destination = regle.port_destination.map_or("".to_string(), |port| format!("--dport {}", port));
    let cible = if action == "bloquer" { "DROP" } else { "ACCEPT" };

    // Construire la commande iptables sous forme de chaine de caracteres
    let commande_iptables = format!("sudo iptables -A INPUT -p {} {} {} {} {} -j {} -m comment --comment {}",
                                    protocole, ip_source, ip_destination, port_source, port_destination, cible, &regle.id);

    // Afficher la commande executee pour le debogage
    println!("Execution de la commande: {}", commande_iptables);

    // Executer la commande iptables
    let sortie = Command::new("sh")
        .arg("-c")
        .arg(&commande_iptables)
        .stderr(Stdio::piped())
        .output()
        .expect("Echec de l'execution de la commande iptables");

    if sortie.status.success() {
        println!("Regle mise a jour dans iptables.");
    } else {
        // Afficher le message d'erreur brut depuis stderr
        let sortie_stderr = String::from_utf8_lossy(&sortie.stderr);
        eprintln!("Echec de la mise a jour de la regle dans iptables. Erreur: {}", sortie_stderr);
    }
}

fn supprimer_regle() {
    // Obtenir les descriptions des regles et la selection
    let (id_regle_selectionnee, selection) = {
        let regles = REGLES.lock().unwrap();
        let descriptions_regles: Vec<String> = regles.iter().map(|regle| format!("{:?}", regle)).collect();

        if descriptions_regles.is_empty() {
            println!("Aucune regle a supprimer.");
            return;
        }

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Selectionnez une regle a supprimer")
            .default(0)
            .items(&descriptions_regles)
            .interact()
            .unwrap();

        // Cloner l'ID pour l'utiliser en dehors de la portee du verrou
        let id_regle_selectionnee = regles[selection].id.clone();
        (id_regle_selectionnee, selection)
    };

    // Maintenant, nous pouvons supprimer la regle iptables en dehors de la portee du verrou
    supprimer_regle_iptables(&id_regle_selectionnee);

    // Maintenant, supprimer la regle de l'application
    let mut regles = REGLES.lock().unwrap();

    regles.remove(selection);

    println!("Regle supprimee.");
}

fn supprimer_regle_iptables(id_regle: &str) {
    // Construire la commande iptables sous forme de chaine de caracteres
    let commande_iptables = format!(
        "sudo iptables -L INPUT --line-numbers | grep -E '{}' | awk '{{print $1}}' | xargs -I {{}} sudo iptables -D INPUT {{}}",
        id_regle
    );

    // Afficher la commande executee pour le debogage
    println!("Execution de la commande: {}", commande_iptables);

    // Executer la commande iptables
    let sortie = Command::new("sh")
        .arg("-c")
        .arg(&commande_iptables)
        .output()
        .expect("Echec de l'execution de la commande iptables");

    // Afficher la sortie de la commande executee pour le debogage
    println!("Sortie de la commande: {:?}", sortie);

    if sortie.status.success() {
        println!("Regle iptables supprimee avec succes pour l'ID de regle: {}", id_regle);
    } else {
        eprintln!("Erreur lors de la suppression de la regle iptables pour l'ID de regle: {}", id_regle);
    }
}

fn voir_logs() {
    println!("Logs du Pare-feu:");
    match fs::read_to_string("parefeu.log") {
        Ok(contenu) => println!("{}", contenu),
        Err(e) => println!("Erreur lors de la lecture du fichier de logs: {}", e),
    }
}

fn traiter_paquets(nom_interface: String) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == nom_interface)
        .expect("Erreur lors de la recherche de l'interface");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("Type de canal non pris en charge"),
        Err(e) => panic!("Erreur lors de la creation du canal de liaison de donnees: {}", e),
    };

    while PAREFEU_EN_COURS.load(Ordering::SeqCst) {
        match rx.next() {
            Ok(paquet) => {
                if let Some(tcp_packet) = TcpPacket::new(paquet) {
                    traiter_paquet_tcp(&tcp_packet);
                }
            },
            Err(e) => eprintln!("Une erreur s'est produite lors de la lecture du paquet: {}", e),
        }
    }
}

fn traiter_paquet_tcp(paquet_tcp: &TcpPacket) {

    let regles = REGLES.lock().unwrap();
    for regle in regles.iter() {
        if paquet_correspond_regle(paquet_tcp, regle) {
            println!("Regle correspondante trouvee");
            match regle.action.as_str() {
                "bloquer" => {
                    enregistrer_action_paquet(paquet_tcp, "Bloque");
                    return; // On abandonne le paquet
                },
                _ => (),
            }
        }
    }

    enregistrer_action_paquet(paquet_tcp, "Autorise");
    // Traitement ou transmission supplementaire du paquet
}

fn paquet_correspond_regle(paquet: &TcpPacket, regle: &Regle) -> bool {
    // Tout d'abord, extraire le paquet IPv4 du paquet TCP
    if let Some(paquet_ipv4) = Ipv4Packet::new(paquet.packet()) {

        // Verifier le protocole (en supposant TCP, car nous travaillons avec TcpPacket)
        if regle.protocole.to_lowercase() != "tcp" {
            return false;
        }

        // Verifier l'IP source
        if let Some(ref regle_ip_source) = regle.ip_source {
            if paquet_ipv4.get_source().to_string() != *regle_ip_source {
                return false;
            }
        }

        // Verifier l'IP de destination
        if let Some(ref regle_ip_destination) = regle.ip_destination {
            if paquet_ipv4.get_destination().to_string() != *regle_ip_destination {
                return false;
            }
        }

        // Verifier le port source
        if let Some(regle_port_source) = regle.port_source {
            if paquet.get_source() != regle_port_source {
                return false;
            }
        }

        // Verifier le port de destination
        if let Some(regle_port_destination) = regle.port_destination {
            if paquet.get_destination() != regle_port_destination {
                return false;
            }
        }

        // Si toutes les verifications passent, le paquet correspond a la regle
        return true;
    }

    false
}

// Enregistrer l'action sur le paquet (soit sur la console, soit dans un fichier)
fn enregistrer_action_paquet(paquet: &TcpPacket, action: &str) {
    let message_log = format!("{} paquet: {:?}, action: {}\n", action, paquet, action);
    let mut fichier = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("parefeu.log")
        .unwrap();

    if let Err(e) = writeln!(fichier, "{}", message_log) {
        eprintln!("Impossible d'ecrire dans le fichier de logs: {}", e);
    }
}

