package com.logitrack_atom.security_service.validation;

import com.logitrack_atom.security_service.config.BootstrapAdminProperties;
import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.stream.Stream;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica normalización, límites de contraseña y protección al inspeccionar DTOs.
 *
 * @author MaxDz
 * @version 0.1.0
 */
class RegistroValidationTest {
    private static final ValidatorFactory FACTORY = Validation.buildDefaultValidatorFactory();

    /** Libera el proveedor real de Bean Validation. */
    @AfterAll
    static void cerrar() { FACTORY.close(); }

    /** Rechaza credenciales que incumplen el contrato de entrada. */
    @ParameterizedTest
    @MethodSource("invalidos")
    void rechazaEntradasInvalidas(RegistroRequest request) {
        assertThat(FACTORY.getValidator().validate(request)).isNotEmpty();
    }

    /** Proporciona casos inválidos, incluyendo el límite en bytes Unicode. */
    static Stream<RegistroRequest> invalidos() {
        return Stream.of(
                new RegistroRequest(null, "password-test-123"),
                new RegistroRequest(" ", "password-test-123"),
                new RegistroRequest("sin-arroba", "password-test-123"),
                new RegistroRequest("ana@example.com", null),
                new RegistroRequest("ana@example.com", " ".repeat(15)),
                new RegistroRequest("ana@example.com", "corta"),
                new RegistroRequest("ana@example.com", "a".repeat(73)),
                new RegistroRequest("ana@example.com", "ñ".repeat(37)));
    }

    /** Acepta los límites representables sin truncar ni modificar la contraseña. */
    @ParameterizedTest
    @MethodSource("contrasenasValidas")
    void aceptaLimitesValidos(String password) {
        var request = new RegistroRequest("  I.USER@EXAMPLE.COM  ", password);
        assertThat(FACTORY.getValidator().validate(request)).isEmpty();
        assertThat(request.email()).isEqualTo("i.user@example.com");
        assertThat(request.password()).isEqualTo(password);
    }

    /** Proporciona valores en los límites de caracteres y bytes UTF-8. */
    static Stream<String> contrasenasValidas() {
        return Stream.of("a".repeat(12), "a".repeat(72), "ñ".repeat(36), "  password-test-123  ");
    }

    /** La representación de ambos contenedores de credenciales excluye el secreto. */
    @Test
    void toStringNoRevelaContrasenas() {
        String password = "solo-secreto-de-prueba";
        assertThat(new RegistroRequest("ana@example.com", password).toString()).doesNotContain(password);
        assertThat(new BootstrapAdminProperties("admin@example.com", password).toString()).doesNotContain(password);
    }
}
