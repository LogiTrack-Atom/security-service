package com.logitrack_atom.security_service.config;

import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comprueba el hash real, su sal aleatoria y la verificación de credenciales.
 *
 * @author MaxDz
 * @version 0.1.0
 */
class PasswordConfigTest {
    /** La misma contraseña produce hashes distintos y solo coincide con el valor correcto. */
    @Test
    void bcryptUsaSalYFactorDoce() {
        var encoder = new PasswordConfig().passwordEncoder();
        String password = UUID.randomUUID().toString();
        String first = encoder.encode(password);
        String second = encoder.encode(password);
        assertThat(first).startsWith("{bcrypt}$2a$12$").isNotEqualTo(second).doesNotContain(password);
        assertThat(encoder.matches(password, first)).isTrue();
        assertThat(encoder.matches("otra-password", first)).isFalse();
    }
}
