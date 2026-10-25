package com.logitrack_atom.security_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.Map;

/**
 * Centraliza el algoritmo de hash adaptativo de las credenciales.
 *
 * @author MaxDz
 * @version 0.1.0
 */
@Configuration
public class PasswordConfig {
    /** Crea la configuración del codificador de contraseñas. */
    public PasswordConfig() { }

    /**
     * Prepara BCrypt con factor 12 y prefijo de algoritmo para futuras migraciones.
     * @return codificador que almacena hashes con formato {bcrypt}
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new DelegatingPasswordEncoder("bcrypt", Map.of("bcrypt", new BCryptPasswordEncoder(12)));
    }
}
