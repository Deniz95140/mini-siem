from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime
from database import Database
from log_collector import LogCollector
from analyzer import SecurityAnalyzer

app = Flask(__name__)
CORS(app)  # Permettre les requêtes depuis le frontend

# Initialiser les composants
db = Database()
collector = LogCollector()
analyzer = SecurityAnalyzer()

# S'assurer que les dossiers existent
os.makedirs('../logs', exist_ok=True)
os.makedirs('../data', exist_ok=True)

@app.route('/')
def index():
    """Servir la page principale"""
    return send_from_directory('../frontend', 'index.html')

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Récupérer les logs récents"""
    limit = request.args.get('limit', 50, type=int)
    # Limiter à maximum 100 pour la performance
    limit = min(limit, 100)
    logs = db.get_recent_logs(limit)
    return jsonify(logs)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Récupérer les alertes récentes"""
    limit = request.args.get('limit', 30, type=int)
    # Limiter à maximum 50 pour la performance
    limit = min(limit, 50)
    alerts = db.get_recent_alerts(limit)
    return jsonify(alerts)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Récupérer les statistiques pour le dashboard"""
    stats = db.get_stats()
    # Ajouter le niveau de menace global
    stats['threat_level'] = analyzer.get_threat_level()
    stats['timestamp'] = datetime.now().isoformat()
    return jsonify(stats)

@app.route('/api/log', methods=['POST'])
def receive_log():
    """Endpoint pour recevoir des logs externes"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    log_data = {
        'source': data.get('source', 'external'),
        'level': data.get('level', 'INFO'),
        'message': data.get('message', ''),
        'ip_address': data.get('ip_address'),
        'user': data.get('user'),
        'raw_log': data.get('raw_log', data.get('message', ''))
    }
    
    # Traiter le log
    collector.process_log(log_data)
    
    return jsonify({'status': 'success'}), 201

@app.route('/api/generate-sample-data', methods=['POST'])
def generate_sample_data():
    """Générer des données d'exemple pour la démo"""
    try:
        collector.generate_sample_logs()
        return jsonify({'status': 'success', 'message': 'Sample data generated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/clear-data', methods=['POST'])
def clear_data():
    """Effacer toutes les données (pour les tests)"""
    try:
        # Recréer la base de données
        db.init_db()
        return jsonify({'status': 'success', 'message': 'Data cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/threat-level', methods=['GET'])
def get_threat_level():
    """Obtenir le niveau de menace actuel"""
    level = analyzer.get_threat_level()
    return jsonify({'threat_level': level})

# Routes pour servir les fichiers statiques du frontend
@app.route('/style.css')
def serve_css():
    return send_from_directory('../frontend', 'style.css')

@app.route('/script.js')
def serve_js():
    return send_from_directory('../frontend', 'script.js')

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🛡️  Mini SIEM - Système de Détection d'Intrusion")
    print("="*50)
    print("\n📌 Le serveur démarre sur http://localhost:5000")
    print("\n💡 Conseils:")
    print("   - Ouvre http://localhost:5000 dans ton navigateur")
    print("   - Clique sur 'Générer des données de test' pour voir le système en action")
    print("   - Les logs et alertes se mettent à jour automatiquement")
    print("\n" + "="*50 + "\n")
    
    # Créer quelques données initiales si la base est vide
    if db.get_stats()['total_logs'] == 0:
        print("🔧 Génération de quelques logs initiaux...")
        collector.generate_sample_logs()
    
    app.run(debug=True, host='0.0.0.0', port=5000)