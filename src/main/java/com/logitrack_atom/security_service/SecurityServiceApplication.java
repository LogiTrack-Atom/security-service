package com.logitrack_atom.security_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Inicia el servicio de identidad de LogiTrack.
 *
 * <p>El registro público es la única operación de negocio habilitada en esta
 * etapa. Se excluye el usuario automático de desarrollo de Spring Security;
 * los usuarios de la aplicación se almacenan en su base independiente.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 */
@SpringBootApplication(excludeName = "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration")
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
