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