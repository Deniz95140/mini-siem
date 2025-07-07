# 🛡️ Mini SIEM - Système de Détection d'Intrusion

Un projet de Blue Teaming pour démontrer les compétences en cybersécurité défensive. Ce mini SIEM collecte, analyse et visualise les logs de sécurité en temps réel.

## 📋 Fonctionnalités

- **Collecte de logs** : Système flexible pour collecter des logs de différentes sources
- **Détection de menaces** : Analyse en temps réel pour détecter :
  - Tentatives de brute force
  - Scans de ports
  - Injections SQL
  - Commandes suspectes
  - Accès non autorisés
- **Dashboard interactif** : Interface web moderne avec :
  - Niveau de menace global
  - Statistiques en temps réel
  - Graphiques dynamiques
  - Alertes de sécurité
  - Visualisation des logs
- **API REST** : Pour intégrer facilement d'autres systèmes

## 🚀 Installation

### Prérequis

- Python 3.7 ou plus récent
- Navigateur web moderne (Chrome, Firefox, Edge)

### Étapes d'installation

1. **Cloner ou créer le projet**
```bash
mkdir mini-siem
cd mini-siem
```

2. **Créer la structure des dossiers**
```bash
mkdir backend frontend logs data
```

3. **Copier tous les fichiers** dans leurs dossiers respectifs :
   - `backend/` : app.py, database.py, analyzer.py, log_collector.py
   - `frontend/` : index.html, style.css, script.js
   - Racine : requirements.txt, README.md

4. **Installer les dépendances Python**
```bash
cd backend
pip install -r ../requirements.txt
```

## 🎮 Utilisation

### Démarrer le serveur

```bash
cd backend
python app.py
```

Le serveur démarre sur `http://localhost:5000`

### Accéder au dashboard

Ouvrir un navigateur et aller sur : `http://localhost:5000`

### Générer des données de test

1. Cliquer sur le bouton "📊 Générer des données de test" dans l'interface
2. Le système va créer des logs et des alertes de démonstration

### Envoyer des logs via l'API

```bash
# Exemple avec curl
curl -X POST http://localhost:5000/api/log \
  -H "Content-Type: application/json" \
  -d '{
    "source": "ssh",
    "level": "ERROR",
    "message": "Failed password for admin from 192.168.1.100",
    "ip_address": "192.168.1.100",
    "user": "admin"
  }'
```

## 🏗️ Architecture

### Backend (Python/Flask)

- **app.py** : Serveur Flask et endpoints API
- **database.py** : Gestion de la base de données SQLite
- **analyzer.py** : Moteur d'analyse et détection de menaces
- **log_collector.py** : Collecte et parsing des logs

### Frontend (HTML/CSS/JS)

- **index.html** : Structure du dashboard
- **style.css** : Design moderne et responsive
- **script.js** : Logique d'affichage et graphiques Chart.js

### Base de données

Tables SQLite :
- `logs` : Stockage de tous les logs
- `alerts` : Alertes de sécurité détectées
- `stats` : Statistiques pour le dashboard

## 🔍 Types de menaces détectées

1. **Brute Force** : 5+ échecs de connexion en 5 minutes
2. **Port Scan** : 10+ ports différents scannés en 2 minutes
3. **SQL Injection** : Patterns SQL malveillants dans les requêtes
4. **Commandes suspectes** : wget, curl, chmod 777, etc.
5. **Accès non autorisés** : Tentatives d'accès refusées

## 📊 API Endpoints

- `GET /` : Dashboard web
- `GET /api/logs` : Récupérer les logs récents
- `GET /api/alerts` : Récupérer les alertes
- `GET /api/stats` : Statistiques du dashboard
- `GET /api/threat-level` : Niveau de menace actuel
- `POST /api/log` : Envoyer un nouveau log
- `POST /api/generate-sample-data` : Générer des données de test
- `POST /api/clear-data` : Effacer toutes les données

## 🎨 Personnalisation

### Ajouter de nouvelles règles de détection

Éditer `analyzer.py` et ajouter une nouvelle méthode dans la classe `SecurityAnalyzer`.

### Modifier les seuils d'alerte

Dans `analyzer.py`, ajuster les valeurs comme :
- Nombre de tentatives pour brute force
- Nombre de ports pour détecter un scan
- Patterns pour SQL injection

### Changer le style

Modifier `style.css` pour personnaliser les couleurs et le design.

## 🚧 Améliorations possibles

- Ajouter l'authentification utilisateur
- Intégrer avec de vrais systèmes de logs (syslog, Windows Event Log)
- Ajouter des notifications par email/SMS
- Créer des rapports PDF
- Ajouter du machine learning pour la détection d'anomalies
- Implémenter un système de règles personnalisables
- Ajouter l'export des données
