package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.config.JwtProperties;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Emite tokens con identidad y roles obtenidos exclusivamente de la cuenta persistida.
 *
 * @author MaxDz
 * @version 0.2.0
 */
@Service
public class JwtTokenService {
    private final JwtEncoder encoder;
    private final JwtProperties properties;
    private final Clock clock;

    /**
     * Recibe firma, contrato y reloj mediante constructor.
     * @param encoder firmante RS256
     * @param properties parámetros del contrato
     * @param clock reloj UTC
     */
    public JwtTokenService(JwtEncoder encoder, JwtProperties properties, Clock clock) {
        this.encoder = encoder;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Genera un token de acceso sin datos de contraseña ni identidad de dominio.
     * @param usuario cuenta que ya superó la autenticación
     * @return token Bearer con duración declarada en segundos
     */
    public TokenResponse emitir(Usuario usuario) {
        var now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(properties.issuer())
                .audience(List.of(properties.audience())).subject(usuario.getId().toString())
                .issuedAt(now).notBefore(now).expiresAt(now.plus(properties.accessTokenTtl()))
                .claim("roles", List.of(usuario.getRol().name())).build();
        var token = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(), claims));
        return new TokenResponse(token.getTokenValue(), "Bearer", properties.accessTokenTtl().toSeconds());
    }
}
