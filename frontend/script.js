// Configuration
const API_URL = 'http://localhost:5000/api';
const UPDATE_INTERVAL = 10000; // Mise à jour toutes les 10 secondes (au lieu de 5)

// Variables globales
let logsChart = null;
let ipsChart = null;
let allLogs = [];
let updateInProgress = false; // Pour éviter les updates multiples

// Fonction pour formater la date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('fr-FR');
}

// Fonction pour formater le temps relatif
function getRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'À l\'instant';
    if (minutes < 60) return `Il y a ${minutes} min`;
    if (hours < 24) return `Il y a ${hours}h`;
    return `Il y a ${days}j`;
}

// Charger les statistiques
async function loadStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const stats = await response.json();
        
        // Mettre à jour les compteurs
        document.getElementById('total-logs').textContent = stats.total_logs || 0;
        document.getElementById('critical-alerts').textContent = stats.alerts_by_severity?.CRITICAL || 0;
        document.getElementById('high-alerts').textContent = stats.alerts_by_severity?.HIGH || 0;
        document.getElementById('medium-alerts').textContent = stats.alerts_by_severity?.MEDIUM || 0;
        
        // Mettre à jour le niveau de menace
        updateThreatLevel(stats.threat_level);
        
        // Mettre à jour les graphiques
        updateLogsChart(stats.logs_by_hour);
        updateIPsChart(stats.top_ips);
        
    } catch (error) {
        console.error('Erreur lors du chargement des stats:', error);
    }
}

// Mettre à jour le niveau de menace
function updateThreatLevel(level) {
    const threatElement = document.getElementById('threat-level');
    const textElement = threatElement.querySelector('.threat-level-text');
    
    // Enlever toutes les classes de niveau
    threatElement.className = 'threat-level';
    
    // Ajouter la classe appropriée et mettre à jour le texte
    switch(level) {
        case 'CRITICAL':
            threatElement.classList.add('critical');
            textElement.textContent = 'CRITIQUE';
            break;
        case 'HIGH':
            threatElement.classList.add('high');
            textElement.textContent = 'ÉLEVÉ';
            break;
        case 'MEDIUM':
            threatElement.classList.add('medium');
            textElement.textContent = 'MOYEN';
            break;
        default:
            threatElement.classList.add('low');
            textElement.textContent = 'FAIBLE';
    }
}

// Charger les alertes
async function loadAlerts() {
    try {
        const response = await fetch(`${API_URL}/alerts?limit=20`); // Limiter à 20 alertes
        const alerts = await response.json();
        
        const container = document.getElementById('alerts-container');
        
        if (alerts.length === 0) {
            container.innerHTML = '<div class="loading">Aucune alerte pour le moment</div>';
            return;
        }
        
        // Limiter l'affichage à 15 alertes
        const alertsToDisplay = alerts.slice(0, 15);
        
        container.innerHTML = alertsToDisplay.map(alert => `
            <div class="alert-item ${alert.severity}">
                <div class="alert-header">
                    <span class="alert-type">${alert.alert_type}</span>
                    <span class="alert-time">${getRelativeTime(alert.timestamp)}</span>
                </div>
                <div class="alert-description">${alert.description.substring(0, 100)}${alert.description.length > 100 ? '...' : ''}</div>
                ${alert.source_ip ? `<div class="alert-details">IP: ${alert.source_ip}</div>` : ''}
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Erreur lors du chargement des alertes:', error);
    }
}

// Charger les logs
async function loadLogs() {
    try {
        const response = await fetch(`${API_URL}/logs?limit=50`); // Limiter à 50 logs
        allLogs = await response.json();
        
        displayLogs(allLogs);
        
    } catch (error) {
        console.error('Erreur lors du chargement des logs:', error);
    }
}

// Afficher les logs
function displayLogs(logs) {
    const container = document.getElementById('logs-container');
    
    if (logs.length === 0) {
        container.innerHTML = '<div class="loading">Aucun log disponible</div>';
        return;
    }
    
    // Limiter à 30 logs pour la performance
    const logsToDisplay = logs.slice(0, 30);
    
    container.innerHTML = logsToDisplay.map(log => `
        <div class="log-item">
            <span class="log-time">${new Date(log.timestamp).toLocaleTimeString('fr-FR')}</span>
            <span class="log-level ${log.level}">${log.level}</span>
            <span class="log-message">${log.message.substring(0, 150)}${log.message.length > 150 ? '...' : ''}</span>
        </div>
    `).join('');
}

// Filtrer les logs
function filterLogs() {
    const filterValue = document.getElementById('log-level-filter').value;
    
    if (!filterValue) {
        displayLogs(allLogs);
    } else {
        const filteredLogs = allLogs.filter(log => log.level === filterValue);
        displayLogs(filteredLogs);
    }
}

// Mettre à jour le graphique des logs
function updateLogsChart(data) {
    const ctx = document.getElementById('logs-chart').getContext('2d');
    
    // Préparer les données - seulement les 12 dernières heures
    const currentHour = new Date().getHours();
    const hours = [];
    const values = [];
    
    for (let i = 11; i >= 0; i--) {
        const hour = (currentHour - i + 24) % 24;
        const hourStr = hour.toString().padStart(2, '0');
        hours.push(`${hourStr}:00`);
        values.push(data[hourStr] || 0);
    }
    
    if (logsChart) {
        logsChart.data.labels = hours;
        logsChart.data.datasets[0].data = values;
        logsChart.update('none'); // Pas d'animation pour l'update
    } else {
        logsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: hours,
                datasets: [{
                    label: 'Logs',
                    data: values,
                    borderColor: '#0090e7',
                    backgroundColor: 'rgba(0, 144, 231, 0.1)',
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 0 // Désactiver les animations
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        padding: 8
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#888',
                            font: { size: 10 }
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: '#888',
                            font: { size: 10 },
                            maxRotation: 0
                        }
                    }
                }
            }
        });
    }
}

// Mettre à jour le graphique des IPs
function updateIPsChart(data) {
    const ctx = document.getElementById('ips-chart').getContext('2d');
    
    // Limiter à 5 IPs pour un graphique plus compact
    const topData = data.slice(0, 5);
    const ips = topData.map(item => item.ip);
    const counts = topData.map(item => item.count);
    
    if (ipsChart) {
        ipsChart.data.labels = ips;
        ipsChart.data.datasets[0].data = counts;
        ipsChart.update('none'); // Pas d'animation
    } else {
        ipsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ips,
                datasets: [{
                    label: 'Requêtes',
                    data: counts,
                    backgroundColor: '#e94560',
                    borderColor: '#e94560',
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 0
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        padding: 8
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#888',
                            font: { size: 10 }
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: '#888',
                            font: { size: 10 },
                            maxRotation: 45,
                            minRotation: 0
                        }
                    }
                }
            }
        });
    }
}

// Générer des données d'exemple
async function generateSampleData() {
    try {
        const response = await fetch(`${API_URL}/generate-sample-data`, {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Données de test générées avec succès!');
            // Recharger toutes les données
            await loadAll();
        } else {
            alert('Erreur lors de la génération des données');
        }
    } catch (error) {
        console.error('Erreur:', error);
        alert('Erreur de connexion au serveur');
    }
}

// Effacer toutes les données
async function clearAllData() {
    if (!confirm('Êtes-vous sûr de vouloir effacer toutes les données?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/clear-data`, {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Données effacées avec succès!');
            await loadAll();
        } else {
            alert('Erreur lors de la suppression des données');
        }
    } catch (error) {
        console.error('Erreur:', error);
        alert('Erreur de connexion au serveur');
    }
}

// Charger toutes les données
async function loadAll() {
    // Éviter les updates multiples simultanés
    if (updateInProgress) return;
    updateInProgress = true;
    
    try {
        // Charger les données de manière séquentielle pour réduire la charge
        await loadStats();
        await new Promise(resolve => setTimeout(resolve, 100)); // Petit délai
        await loadAlerts();
        await new Promise(resolve => setTimeout(resolve, 100)); // Petit délai
        await loadLogs();
    } finally {
        updateInProgress = false;
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    // Charger les données initiales
    loadAll();
    
    // Mettre à jour automatiquement avec un intervalle plus long
    setInterval(loadAll, UPDATE_INTERVAL);
    
    // Supprimer l'indicateur de mise à jour qui consomme des ressources
});