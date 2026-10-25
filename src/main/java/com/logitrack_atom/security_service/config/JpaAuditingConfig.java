package com.logitrack_atom.security_service.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Habilita las fechas de auditoría administradas por Spring Data JPA.
 *
 * @author MaxDz
 * @version 0.1.0
 */
@Configuration
@EnableJpaAuditing
public class JpaAuditingConfig {
    /** Crea la configuración de auditoría de persistencia. */
    public JpaAuditingConfig() { }
 }
