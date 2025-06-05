-- Esquema de la base de datos para el sistema de auditoría de seguridad

-- Tabla de redes
CREATE TABLE IF NOT EXISTS networks (
    network_id VARCHAR(50) PRIMARY KEY,
    hosts JSONB NOT NULL DEFAULT '[]',
    routes JSONB NOT NULL DEFAULT '[]',
    services JSONB NOT NULL DEFAULT '[]',
    subnets JSONB NOT NULL DEFAULT '[]',
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de objetivos
CREATE TABLE IF NOT EXISTS targets (
    target_id VARCHAR(50) PRIMARY KEY,
    info JSONB NOT NULL DEFAULT '{}',
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de vulnerabilidades
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    cvss DECIMAL(3,1),
    target VARCHAR(50) NOT NULL,
    discovered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- Tabla de credenciales
CREATE TABLE IF NOT EXISTS credentials (
    cred_id VARCHAR(50) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    service VARCHAR(50) NOT NULL,
    target VARCHAR(50) NOT NULL,
    discovered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_networks_last_updated ON networks(last_updated);
CREATE INDEX IF NOT EXISTS idx_targets_last_updated ON targets(last_updated);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target ON vulnerabilities(target);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_credentials_target ON credentials(target);
CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);

-- Vistas
CREATE OR REPLACE VIEW network_summary AS
SELECT 
    n.network_id,
    jsonb_array_length(n.hosts) as total_hosts,
    jsonb_array_length(n.routes) as total_routes,
    jsonb_array_length(n.services) as total_services,
    jsonb_array_length(n.subnets) as total_subnets,
    n.last_updated
FROM networks n;

CREATE OR REPLACE VIEW vulnerability_summary AS
SELECT 
    t.target_id,
    COUNT(v.vuln_id) as total_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'medium' THEN 1 END) as medium_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'low' THEN 1 END) as low_vulnerabilities,
    MAX(v.discovered_at) as last_vulnerability_discovered
FROM targets t
LEFT JOIN vulnerabilities v ON t.target_id = v.target
GROUP BY t.target_id;

CREATE OR REPLACE VIEW credential_summary AS
SELECT 
    t.target_id,
    COUNT(c.cred_id) as total_credentials,
    COUNT(DISTINCT c.service) as unique_services,
    MAX(c.discovered_at) as last_credential_discovered
FROM targets t
LEFT JOIN credentials c ON t.target_id = c.target
GROUP BY t.target_id; 