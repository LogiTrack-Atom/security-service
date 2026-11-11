package com.logitrack_atom.security_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Recibe las credenciales externas del aprovisionamiento inicial de ADMIN.
 *
 * @param email correo suministrado por el operador
 * @param password contraseña externa, nunca incorporada al repositorio
 * @author MaxDz
 * @version 0.1.0
 */
@ConfigurationProperties("logitrack.bootstrap-admin")
public record BootstrapAdminProperties(String email, String password) {
    /**
     * Evita incluir las credenciales al inspeccionar la configuración.
     * @return descripción sin secretos
     */
    @Override
    public String toString() { return "BootstrapAdminProperties[credenciales protegidas]"; }
}
