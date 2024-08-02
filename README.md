# Firewall en Rust

## Vue d'ensemble

Ce projet est un pare-feu en ligne de commande en Rust. Il permet aux utilisateurs de définir des règles pour accepter ou rejeter les paquets réseau entrants selon des critères spécifiés.

## Prérequis

Avant de commencer, assurez-vous d'avoir Rust installé sur votre système. Suivez le guide d'installation de Rust pour obtenir des instructions.

## Pour commencer

Clonez ce dépôt et accédez au répertoire du projet:
Copier le code
``git clone [URL de votre dépôt]
cd rust_firewall``

## Fonctionnalités

**Définition des règles**: Définir des règles basées sur l'IP source, le port de destination et d'autres critères.

**Gestion des règles**: Ajouter, supprimer et lister les règles du pare-feu.

**Intégration avec Iptables**: Mettre à jour iptables selon les règles définies.

**Interface en ligne de commande**: CLI facile à utiliser pour gérer le pare-feu.

**Traitement des paquets**: Traiter les paquets entrants et appliquer les règles.

**Journalisation**: Journaliser les paquets acceptés et rejetés pour le suivi.

**Gestion des erreurs**: Gérer les erreurs de manière élégante et fournir des messages informatifs.
