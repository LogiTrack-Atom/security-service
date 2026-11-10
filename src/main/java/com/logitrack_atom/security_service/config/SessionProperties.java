package com.logitrack_atom.security_service.config;

import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Política de renovación del navegador; no contiene secretos.
 * @param origin origen público exacto que puede usar la cookie
 * @param ttl vida absoluta de renovación, positiva y de hasta un día
 */
@ConfigurationProperties("logitrack.session")
public record SessionProperties(String origin, Duration ttl) {
    /** Valida la configuración y permite HTTP únicamente para localhost de pruebas.
     * @param origin origen exacto, sin ruta ni credenciales
     * @param ttl duración absoluta de la familia
     */
    public SessionProperties {
        origin = origin == null ? "https://localhost" : origin;
        ttl = ttl == null ? Duration.ofHours(8) : ttl;
        URI uri = URI.create(origin);
        if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null || !uri.getRawPath().isEmpty()
                || uri.getPort() == 0 || uri.getPort() > 65535
                || !("https".equals(uri.getScheme()) || ("http".equals(uri.getScheme()) && "localhost".equals(uri.getHost())))
                || ttl.isZero() || ttl.isNegative() || ttl.getNano() != 0 || ttl.compareTo(Duration.ofDays(1)) > 0) {
            throw new IllegalArgumentException("Política de sesión inválida: usar origen HTTPS exacto y duración acotada.");
        }
    }
}
