package com.logitrack_atom.security_service.bootstrap;

import com.logitrack_atom.security_service.config.BootstrapAdminProperties;
import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.service.UsuarioService;
import jakarta.validation.Validator;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Aprovisiona ADMIN solo cuando el operador habilita explícitamente el bootstrap.
 *
 * <p>Valida las credenciales antes de acceder al servicio. Una configuración
 * inválida detiene el arranque sin imprimir el valor de la contraseña.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 * @see UsuarioService#asegurarAdministradorInicial(RegistroRequest)
 */
@Component
@ConditionalOnProperty(prefix = "logitrack.bootstrap-admin", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(BootstrapAdminProperties.class)
public class AdminBootstrapRunner implements ApplicationRunner {
    private final BootstrapAdminProperties properties;
    private final Validator validator;
    private final UsuarioService usuarios;

    /**
     * Recibe configuración, validación y negocio por constructor.
     * @param properties credenciales externas
     * @param validator validador del contrato de registro
     * @param usuarios servicio de cuentas
     */
    public AdminBootstrapRunner(BootstrapAdminProperties properties, Validator validator, UsuarioService usuarios) {
        this.properties = properties;
        this.validator = validator;
        this.usuarios = usuarios;
    }

    /**
     * Ejecuta el alta inicial sin restablecer contraseñas existentes.
     * @param args argumentos de arranque, no utilizados como credenciales
     * @throws IllegalStateException si falta configuración o la cuenta pertenece a otro rol
     */
    @Override
    public void run(ApplicationArguments args) {
        RegistroRequest request = new RegistroRequest(properties.email(), properties.password());
        if (!validator.validate(request).isEmpty()) {
            throw new IllegalStateException("Las credenciales del administrador inicial son incompletas o inválidas.");
        }
        usuarios.asegurarAdministradorInicial(request);
    }
}
