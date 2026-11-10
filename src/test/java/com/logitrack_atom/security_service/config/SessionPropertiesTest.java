package com.logitrack_atom.security_service.config;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

/** Evita ampliar por configuración el origen CSRF o la ventana de renovación. */
class SessionPropertiesTest {
    /** Orígenes inseguros o ambiguos impiden arrancar. */
    @ParameterizedTest
    @ValueSource(strings = {"http://public.example.test", "https://*.example.test", "https://user@example.test", "https://example.test/path", "https://example.test#fragment", "https://example.test:0", "https://example.test:65536"})
    void rechazaOrigenInseguro(String origin) {
        assertThatThrownBy(() -> new SessionProperties(origin, Duration.ofHours(8))).isInstanceOf(IllegalArgumentException.class);
    }
    /** Solo localhost permite HTTP y el TTL absoluto no puede ser infinito. */
    @Test void limitaDuracionYLocalhost() {
        assertThat(new SessionProperties("http://localhost:8080", null).ttl()).isEqualTo(Duration.ofHours(8));
        for (var ttl : new Duration[]{Duration.ZERO, Duration.ofSeconds(-1), Duration.ofDays(2), Duration.ofNanos(1)}) {
            assertThatThrownBy(() -> new SessionProperties("https://example.test", ttl)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
