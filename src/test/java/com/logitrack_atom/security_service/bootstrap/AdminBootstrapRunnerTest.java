package com.logitrack_atom.security_service.bootstrap;

import com.logitrack_atom.security_service.config.BootstrapAdminProperties;
import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.service.UsuarioService;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Verifica que un bootstrap mal configurado falle antes de persistir credenciales.
 *
 * @author MaxDz
 * @version 0.1.0
 */
class AdminBootstrapRunnerTest {
    private static final ValidatorFactory FACTORY = Validation.buildDefaultValidatorFactory();

    /** Libera el validador utilizado por los casos de arranque. */
    @AfterAll
    static void cerrar() { FACTORY.close(); }

    /** Las credenciales faltantes no invocan el servicio de cuentas. */
    @ParameterizedTest
    @NullAndEmptySource
    void rechazaContrasenaAusente(String password) {
        UsuarioService service = mock(UsuarioService.class);
        var runner = new AdminBootstrapRunner(new BootstrapAdminProperties("admin@example.com", password),
                FACTORY.getValidator(), service);
        assertThatThrownBy(() -> runner.run(null)).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(service);
    }

    /** Una contraseña inválida no se incluye en el error de arranque. */
    @Test
    void errorNoRevelaValorRecibido() {
        UsuarioService service = mock(UsuarioService.class);
        var runner = new AdminBootstrapRunner(new BootstrapAdminProperties("admin@example.com", "corta"),
                FACTORY.getValidator(), service);
        assertThatThrownBy(() -> runner.run(null))
                .isInstanceOf(IllegalStateException.class).hasMessageNotContaining("corta");
        verifyNoInteractions(service);
    }

    /** Entrega al servicio las credenciales válidas con correo normalizado. */
    @Test
    void delegaElBootstrapValido() {
        UsuarioService service = mock(UsuarioService.class);
        var runner = new AdminBootstrapRunner(new BootstrapAdminProperties(" ADMIN@example.com ", "password-test-123"),
                FACTORY.getValidator(), service);
        runner.run(null);
        verify(service).asegurarAdministradorInicial(new RegistroRequest("admin@example.com", "password-test-123"));
    }
}
