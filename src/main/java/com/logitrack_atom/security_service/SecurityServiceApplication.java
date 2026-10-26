package com.logitrack_atom.security_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.logitrack_atom.security_service.config.ConfigMarkerProperties;

/**
 * Inicia el servicio de identidad de LogiTrack.
 *
 * <p>Expone registro, login, identidad JWT y administración. Dev y prod cargan
 * sus propiedades desde Config Server antes de iniciar la API. Se excluye el
 * usuario automático de desarrollo de Spring Security; las cuentas se
 * almacenan en una base independiente y las claves se cargan de archivos externos.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
@SpringBootApplication(excludeName = "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration")
@EnableConfigurationProperties(ConfigMarkerProperties.class)
public class SecurityServiceApplication {
    /** Crea la configuración principal del servicio. */
    public SecurityServiceApplication() { }


    /**
     * Arranca el contexto y la API REST.
     * @param args argumentos de ejecución, sin credenciales embebidas
     */
    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }
}
