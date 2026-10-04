CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(36) NOT NULL,
    target_url TEXT NOT NULL,
    target_name VARCHAR(100) NOT NULL,
    parameter_name VARCHAR(100) DEFAULT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'QUEUED',
    error_message TEXT DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP NULL DEFAULT NULL,
    completed_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id VARCHAR(36) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    tested_url TEXT NOT NULL,
    parameter_name VARCHAR(100) DEFAULT NULL,
    evidence TEXT DEFAULT NULL,
    baseline_ms INT UNSIGNED DEFAULT NULL,
    observed_ms INT UNSIGNED DEFAULT NULL,
    http_status SMALLINT UNSIGNED DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_findings_scan_id (scan_id),
    CONSTRAINT fk_findings_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_scan_events_scan_id (scan_id),
    CONSTRAINT fk_scan_events_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(id)
        ON DELETE CASCADE
);