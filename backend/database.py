import sqlite3
from datetime import datetime
import json
import os

class Database:
    def __init__(self, db_path='../data/siem.db'):
        self.db_path = db_path
        # Créer le dossier data s'il n'existe pas
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """Créer les tables si elles n'existent pas"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table pour stocker tous les logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                level TEXT,
                message TEXT,
                ip_address TEXT,
                user TEXT,
                raw_log TEXT
            )
        ''')
        
        # Table pour les alertes de sécurité
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                severity TEXT,
                description TEXT,
                source_ip TEXT,
                details TEXT
            )
        ''')
        
        # Table pour les statistiques
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                stat_type TEXT,
                value INTEGER,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_log(self, source, level, message, ip_address=None, user=None, raw_log=None):
        """Ajouter un log dans la base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (source, level, message, ip_address, user, raw_log)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (source, level, message, ip_address, user, raw_log))
        
        conn.commit()
        conn.close()
    
    def add_alert(self, alert_type, severity, description, source_ip=None, details=None):
        """Ajouter une alerte de sécurité"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (alert_type, severity, description, source_ip, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, description, source_ip, json.dumps(details) if details else None))
        
        conn.commit()
        conn.close()
    
    def get_recent_logs(self, limit=100):
        """Récupérer les logs récents"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM logs
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return logs
    
    def get_recent_alerts(self, limit=50):
        """Récupérer les alertes récentes"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return alerts
    
    def get_stats(self):
        """Récupérer les statistiques pour le dashboard"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Nombre total de logs
        cursor.execute('SELECT COUNT(*) FROM logs')
        stats['total_logs'] = cursor.fetchone()[0]
        
        # Nombre d'alertes par sévérité
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        stats['alerts_by_severity'] = dict(cursor.fetchall())
        
        # Logs par heure (dernières 24h)
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM logs
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        ''')
        stats['logs_by_hour'] = dict(cursor.fetchall())
        
        # IPs les plus actives
        cursor.execute('''
            SELECT ip_address, COUNT(*) as count
            FROM logs
            WHERE ip_address IS NOT NULL
            GROUP BY ip_address
            ORDER BY count DESC
            LIMIT 10
        ''')
        stats['top_ips'] = [dict(ip=row[0], count=row[1]) for row in cursor.fetchall()]
        
        conn.close()
        return stats