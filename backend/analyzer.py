import re
from datetime import datetime, timedelta
from collections import defaultdict
from database import Database

class SecurityAnalyzer:
    def __init__(self):
        self.db = Database()
        # Dictionnaire pour tracker les tentatives par IP
        self.failed_attempts = defaultdict(list)
        self.port_scans = defaultdict(list)
        
    def analyze_log(self, log_data):
        """Analyser un log et détecter les menaces potentielles"""
        # Extraire les infos importantes du log
        ip_address = log_data.get('ip_address')
        message = log_data.get('message', '').lower()
        source = log_data.get('source', '')
        
        # Vérifier différents types de menaces
        self.check_brute_force(ip_address, message)
        self.check_port_scan(ip_address, message)
        self.check_sql_injection(message)
        self.check_suspicious_commands(ip_address, message)
        self.check_unauthorized_access(ip_address, message)
        
    def check_brute_force(self, ip_address, message):
        """Détecter les tentatives de brute force"""
        if not ip_address:
            return
            
        # Patterns pour détecter les échecs de connexion
        fail_patterns = [
            'failed password',
            'authentication failure',
            'invalid user',
            'failed login',
            'access denied',
            'incorrect password'
        ]
        
        if any(pattern in message for pattern in fail_patterns):
            now = datetime.now()
            self.failed_attempts[ip_address].append(now)
            
            # Garder seulement les tentatives des 5 dernières minutes
            self.failed_attempts[ip_address] = [
                t for t in self.failed_attempts[ip_address]
                if now - t < timedelta(minutes=5)
            ]
            
            # Si plus de 5 tentatives en 5 minutes = alerte
            if len(self.failed_attempts[ip_address]) >= 5:
                self.db.add_alert(
                    alert_type='BRUTE_FORCE',
                    severity='HIGH',
                    description=f'Tentative de brute force détectée: {len(self.failed_attempts[ip_address])} échecs en 5 minutes',
                    source_ip=ip_address,
                    details={'attempts': len(self.failed_attempts[ip_address])}
                )
                # Reset le compteur après l'alerte
                self.failed_attempts[ip_address] = []
    
    def check_port_scan(self, ip_address, message):
        """Détecter les scans de ports"""
        if not ip_address:
            return
            
        # Patterns pour détecter les connexions sur différents ports
        port_pattern = r'port (\d+)'
        port_match = re.search(port_pattern, message)
        
        if port_match and ('connection' in message or 'attempt' in message):
            port = port_match.group(1)
            now = datetime.now()
            
            # Tracker les ports accédés par cette IP
            self.port_scans[ip_address].append((now, port))
            
            # Garder seulement les accès des 2 dernières minutes
            self.port_scans[ip_address] = [
                (t, p) for t, p in self.port_scans[ip_address]
                if now - t < timedelta(minutes=2)
            ]
            
            # Si plus de 10 ports différents en 2 minutes = scan
            unique_ports = set(p for _, p in self.port_scans[ip_address])
            if len(unique_ports) >= 10:
                self.db.add_alert(
                    alert_type='PORT_SCAN',
                    severity='MEDIUM',
                    description=f'Scan de ports détecté: {len(unique_ports)} ports scannés',
                    source_ip=ip_address,
                    details={'ports': list(unique_ports)}
                )
                self.port_scans[ip_address] = []
    
    def check_sql_injection(self, message):
        """Détecter les tentatives d'injection SQL"""
        sql_patterns = [
            r"union.*select",
            r"select.*from.*where",
            r"drop\s+table",
            r"insert\s+into",
            r"delete\s+from",
            r"update.*set",
            r"or\s+1\s*=\s*1",
            r";\s*--",
            r"xp_cmdshell",
            r"exec\s+sp_",
            r"cast\s*\(",
            r"convert\s*\("
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                # Essayer d'extraire l'IP si présente dans le message
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                ip = ip_match.group(1) if ip_match else 'Unknown'
                
                self.db.add_alert(
                    alert_type='SQL_INJECTION',
                    severity='CRITICAL',
                    description='Tentative d\'injection SQL détectée',
                    source_ip=ip,
                    details={'pattern': pattern, 'message': message[:200]}
                )
                break
    
    def check_suspicious_commands(self, ip_address, message):
        """Détecter l'exécution de commandes suspectes"""
        suspicious_commands = [
            'wget', 'curl', 'nc -e', 'bash -i',
            '/etc/passwd', '/etc/shadow',
            'chmod 777', 'rm -rf',
            'base64 -d', 'eval(',
            'powershell -e', 'cmd.exe',
            '.onion', 'tor',
            'cryptocurrency', 'bitcoin',
            'ransomware', 'encrypt'
        ]
        
        for cmd in suspicious_commands:
            if cmd in message:
                self.db.add_alert(
                    alert_type='SUSPICIOUS_COMMAND',
                    severity='HIGH',
                    description=f'Commande suspecte détectée: {cmd}',
                    source_ip=ip_address,
                    details={'command': cmd, 'full_message': message[:200]}
                )
                break
    
    def check_unauthorized_access(self, ip_address, message):
        """Détecter les accès non autorisés"""
        unauthorized_patterns = [
            'unauthorized access',
            'permission denied',
            'access forbidden',
            'not authorized',
            'invalid token',
            'session expired',
            'invalid api key'
        ]
        
        for pattern in unauthorized_patterns:
            if pattern in message:
                self.db.add_alert(
                    alert_type='UNAUTHORIZED_ACCESS',
                    severity='MEDIUM',
                    description='Tentative d\'accès non autorisé',
                    source_ip=ip_address,
                    details={'pattern': pattern}
                )
                break
    
    def get_threat_level(self):
        """Calculer le niveau de menace global"""
        # Compter les alertes des dernières 24h
        recent_alerts = self.db.get_recent_alerts(100)
        
        critical_count = sum(1 for alert in recent_alerts if alert['severity'] == 'CRITICAL')
        high_count = sum(1 for alert in recent_alerts if alert['severity'] == 'HIGH')
        medium_count = sum(1 for alert in recent_alerts if alert['severity'] == 'MEDIUM')
        
        # Calculer un score de menace
        threat_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2)
        
        if threat_score >= 50:
            return 'CRITICAL'
        elif threat_score >= 20:
            return 'HIGH'
        elif threat_score >= 10:
            return 'MEDIUM'
        else:
            return 'LOW'