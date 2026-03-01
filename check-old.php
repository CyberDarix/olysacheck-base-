<?php
/**
 * OLYSA CHECK - API DE VÉRIFICATION D'EMAIL
 * Connexion sécurisée entre le site et TiDB Cloud
 * Version: 2.0.0 SECURISEE
 */

// ==============================================
// 1. CONFIGURATION AVEC VARIABLES D'ENVIRONNEMENT
// ==============================================
define('DB_HOST', getenv('DB_HOST') ?: 'gateway01.eu-central-1.prod.aws.tidbcloud.com');
define('DB_PORT', getenv('DB_PORT') ?: 4000);
define('DB_NAME', getenv('DB_NAME') ?: 'test');
define('DB_USER', getenv('DB_USER') ?: '');
define('DB_PASS', getenv('DB_PASS') ?: '');
define('CA_CERT_PATH', getenv('CA_CERT_PATH') ?: __DIR__ . '/isgrootx1.pem');
define('API_SECRET_KEY', getenv('API_SECRET_KEY') ?: '');

// ==============================================
// 2. VÉRIFICATION QUE LES SECRETS SONT PRÉSENTS
// ==============================================
if (empty(DB_USER) || empty(DB_PASS) || empty(API_SECRET_KEY)) {
    error_log("Erreur: Variables d'environnement manquantes");
    sendError(500, 'Configuration serveur incomplète', true);
}

// ==============================================
// 3. EN-TÊTES DE SÉCURITÉ
// ==============================================
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Access-Control-Allow-Origin: https://olysacheck.vercel.app');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
header('Access-Control-Max-Age: 86400');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ==============================================
// 4. VALIDATION DE LA REQUÊTE
// ==============================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendError(405, 'Méthode non autorisée. Utilisez POST.');
}

$headers = function_exists('getallheaders') ? getallheaders() : [];
$apiKey = $headers['X-API-Key'] ?? $_SERVER['HTTP_X_API_KEY'] ?? '';

if ($apiKey !== API_SECRET_KEY) {
    sendError(401, 'Clé API invalide ou manquante');
}

$input = json_decode(file_get_contents('php://input'), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    sendError(400, 'Format JSON invalide');
}

$email = trim($input['email'] ?? '');
if (empty($email)) {
    sendError(400, 'L\'email est requis');
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    sendError(400, 'Format d\'email invalide');
}

// ==============================================
// 5. CONNEXION À TIDB CLOUD
// ==============================================
try {
    if (!file_exists(CA_CERT_PATH)) {
        throw new Exception("Certificat introuvable: " . CA_CERT_PATH);
    }
    
    $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => 10,
        PDO::MYSQL_ATTR_SSL_CA => CA_CERT_PATH,
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
    ];
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    
} catch (Exception $e) {
    error_log("Erreur DB: " . $e->getMessage());
    sendError(503, 'Service temporairement indisponible', true);
}

// ==============================================
// 6. VÉRIFICATION DE L'EMAIL
// ==============================================
try {
    $emailHash = hash('sha256', strtolower($email));

    $stmt = $pdo->prepare("
        SELECT 
            b.breach_name,
            b.breach_date,
            b.severity,
            b.description,
            b.category,
            ce.exposed_data,
            ce.first_seen
        FROM compromised_emails ce
        LEFT JOIN breaches b ON ce.breach_id = b.id
        WHERE ce.email_hash = ?
        ORDER BY b.breach_date DESC
    ");
    
    $stmt->execute([$emailHash]);
    $breaches = $stmt->fetchAll();

    // Calcul du risque
    $totalBreaches = count($breaches);
    $riskScore = min(0.1 + ($totalBreaches * 0.15), 0.95);
    
    $severityCount = [
        'critical' => 0,
        'high'     => 0,
        'medium'   => 0,
        'low'      => 0
    ];

    foreach ($breaches as $breach) {
        $sev = $breach['severity'] ?? 'low';
        if (isset($severityCount[$sev])) {
            $severityCount[$sev]++;
        }
    }

    // Construction de la réponse
    $response = [
        'success' => true,
        'data'    => [
            'email'       => maskEmail($email),
            'email_hash'  => $emailHash,
            'verified_at' => date('c'),
            'risk'        => [
                'score'      => round($riskScore * 100, 1),
                'level'      => getRiskLevel($riskScore),
                'confidence' => 80
            ],
            'breaches' => [
                'total'       => $totalBreaches,
                'found'       => !empty($breaches),
                'details'     => array_map(function($breach) {
                    return [
                        'name'            => $breach['breach_name'] ?? 'Inconnu',
                        'date'            => $breach['breach_date'] ?? null,
                        'severity'        => $breach['severity'] ?? 'low',
                        'description'     => $breach['description'] ?? '',
                        'category'        => $breach['category'] ?? '',
                        'data_exposed'    => $breach['exposed_data'] ? json_decode($breach['exposed_data'], true) : [],
                        'first_seen'      => $breach['first_seen'] ?? null,
                    ];
                }, $breaches),
                'by_severity' => $severityCount
            ],
            'recommendations' => [
                'primary' => generateRecommendations($riskScore, $totalBreaches, $severityCount)[0] ?? 'Aucune recommandation',
                'steps'   => generateRecommendations($riskScore, $totalBreaches, $severityCount)
            ]
        ],
        'meta' => [
            'api_version'      => '2.0.0',
            'response_time_ms' => round((microtime(true) - $_SERVER['REQUEST_TIME_FLOAT']) * 1000),
            'database'         => 'TiDB Cloud'
        ]
    ];

    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

} catch (PDOException $e) {
    error_log("Erreur requête: " . $e->getMessage());
    sendError(500, 'Erreur lors de l\'analyse', true);
} catch (Exception $e) {
    error_log("Erreur applicative: " . $e->getMessage());
    sendError(500, 'Erreur interne du serveur', true);
}

// ==============================================
// FONCTIONS UTILITAIRES
// ==============================================
function sendError($code, $message, $isTechnical = false) {
    http_response_code($code);
    echo json_encode([
        'success' => false,
        'error'   => [
            'code'      => $code,
            'message'   => $message,
            'technical' => $isTechnical
        ]
    ], JSON_PRETTY_PRINT);
    exit();
}

function maskEmail($email) {
    $parts = explode('@', $email);
    $name = $parts[0];
    $domain = $parts[1];
    $maskedName = substr($name, 0, 3) . str_repeat('*', max(0, strlen($name) - 3));
    return $maskedName . '@' . $domain;
}

function getRiskLevel($score) {
    if ($score > 0.8) return 'CRITIQUE';
    if ($score > 0.6) return 'ÉLEVÉ';
    if ($score > 0.3) return 'MOYEN';
    if ($score > 0.1) return 'FAIBLE';
    return 'TRÈS FAIBLE';
}

function generateRecommendations($risk, $totalBreaches, $severityCount) {
    $steps = [];

    if ($risk > 0.8 || ($severityCount['critical'] ?? 0) > 0) {
        $steps[] = "🔴 **ACTION IMMÉDIATE REQUISE** : Changez tous vos mots de passe maintenant";
        $steps[] = "🔴 Activez l'authentification à deux facteurs sur tous vos comptes";
        $steps[] = "🔴 Vérifiez vos comptes bancaires et cartes de crédit";
    }

    if ($totalBreaches > 5) {
        $steps[] = "⚠️ Vous êtes dans " . $totalBreaches . " fuites - utilisez un gestionnaire de mots de passe";
    }

    if (($severityCount['high'] ?? 0) > 0) {
        $steps[] = "⚠️ Changez les mots de passe des comptes concernés par des fuites de sévérité ÉLEVÉE";
    }

    if ($risk > 0.3) {
        $steps[] = "🔄 Surveillez régulièrement vos comptes pour détecter toute activité suspecte";
        $steps[] = "📧 Méfiez-vous des emails de phishing qui pourraient utiliser ces données";
    }

    if ($risk <= 0.3 && $totalBreaches === 0) {
        $steps[] = "✅ Continuez vos bonnes pratiques de sécurité";
        $steps[] = "🔐 Activez la double authentification si ce n'est pas déjà fait";
    }

    return $steps;
}