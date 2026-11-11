package com.logitrack_atom.security_service.validation;

import com.logitrack_atom.security_service.dto.request.UsuarioCreateRequest;
import com.logitrack_atom.security_service.enums.Rol;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.util.stream.Stream;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica el contrato administrativo con Bean Validation y límites UTF-8 reales.
 *
 * @author MaxDz
 * @version 0.2.0
 */
class UsuarioCreateValidationTest {
    private static final ValidatorFactory FACTORY = Validation.buildDefaultValidatorFactory();

    /** Libera los recursos del proveedor de validación. */
    @AfterAll
    static void cerrar() { FACTORY.close(); }

    /** Rechaza credenciales inválidas y la ausencia de un rol administrativo explícito. */
    @ParameterizedTest
    @MethodSource("invalidos")
    void rechazaEntradaInvalida(UsuarioCreateRequest request) {
        assertThat(FACTORY.getValidator().validate(request)).isNotEmpty();
    }

    /** Proporciona casos de correo, contraseña y rol fuera del contrato. */
    static Stream<UsuarioCreateRequest> invalidos() {
        return Stream.of(
                new UsuarioCreateRequest(null, "password-test-123", Rol.ADMIN),
                new UsuarioCreateRequest(" ", "password-test-123", Rol.ADMIN),
                new UsuarioCreateRequest("sin-arroba", "password-test-123", Rol.ADMIN),
                new UsuarioCreateRequest("a".repeat(250) + "@example.com", "password-test-123", Rol.ADMIN),
                new UsuarioCreateRequest("ana@example.com", null, Rol.ADMIN),
                new UsuarioCreateRequest("ana@example.com", " ".repeat(15), Rol.ADMIN),
                new UsuarioCreateRequest("ana@example.com", "corta", Rol.ADMIN),
                new UsuarioCreateRequest("ana@example.com", "a".repeat(73), Rol.ADMIN),
                new UsuarioCreateRequest("ana@example.com", "ñ".repeat(37), Rol.ADMIN),
                new UsuarioCreateRequest("ana@example.com", "password-test-123", null));
    }

    /** La contraseña se conserva sin alteraciones y nunca aparece en el diagnóstico del DTO. */
    @Test
    void normalizaSoloCorreoYOcultaCredenciales() {
        String password = "  contraseña-ejemplo  ";
        var request = new UsuarioCreateRequest("  I.USER@EXAMPLE.COM ", password, Rol.REPARTIDOR);
        assertThat(FACTORY.getValidator().validate(request)).isEmpty();
        assertThat(request.email()).isEqualTo("i.user@example.com");
        assertThat(request.password()).isEqualTo(password);
        assertThat(request.toString()).doesNotContain(password, request.email());
    }

    /** Se aceptan los límites de bytes sin truncamiento previo a BCrypt. */
    @ParameterizedTest
    @MethodSource("passwordsValidas")
    void aceptaLimitesDeContrasena(String password) {
        assertThat(FACTORY.getValidator().validate(
                new UsuarioCreateRequest("ana@example.com", password, Rol.CLIENTE))).isEmpty();
    }

    /** Proporciona los extremos de longitud por caracteres y bytes. */
    static Stream<String> passwordsValidas() {
        return Stream.of("a".repeat(12), "a".repeat(72), "ñ".repeat(36));
    }
}
