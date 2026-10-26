package com.logitrack_atom.security_service.config;

import com.logitrack_atom.security_service.security.JwtContractValidator;
import com.logitrack_atom.security_service.security.RsaKeyLoader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;

/**
 * Configura firma RS256 y validación local sin discovery ni introspección remota.
 *
 * @author MaxDz
 * @version 0.2.0
 */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {
    /** Crea la configuración criptográfica del servicio. */
    public JwtConfig() { }

    /**
     * Proporciona el reloj compartido de emisión y validación.
     * @return reloj UTC del sistema
     */
    @Bean
    public Clock jwtClock() { return Clock.systemUTC(); }

    /**
     * Carga el par externo y rechaza configuraciones inválidas al arrancar.
     * @param properties ubicaciones de claves
     * @param loader cargador local
     * @return par RSA verificado
     */
    @Bean
    public KeyPair jwtKeyPair(JwtProperties properties, RsaKeyLoader loader) {
        return loader.cargar(properties.privateKeyLocation(), properties.publicKeyLocation());
    }

    /**
     * Separa la clave de verificación del material privado del emisor.
     * @param keys par configurado
     * @return únicamente la clave pública
     */
    @Bean
    public RSAPublicKey jwtPublicKey(KeyPair keys) { return (RSAPublicKey) keys.getPublic(); }

    /**
     * Prepara el codificador que firma los tokens del servicio.
     * @param keys par RSA exclusivo del emisor
     * @return codificador JWT con clave privada local
     */
    @Bean
    public JwtEncoder jwtEncoder(KeyPair keys) {
        RSAKey key = new RSAKey.Builder((RSAPublicKey) keys.getPublic())
                .privateKey((RSAPrivateKey) keys.getPrivate()).build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    /**
     * Valida exclusivamente RS256 con una clave pública y los claims acordados.
     * @param publicKey clave pública local
     * @param properties emisor, audiencia y límites de tiempo
     * @param clock reloj utilizado por los validadores
     * @return decoder que no realiza consultas HTTP
     */
    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey publicKey, JwtProperties properties, Clock clock) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        JwtTimestampValidator timestamp = new JwtTimestampValidator(properties.clockSkew());
        timestamp.setClock(clock);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestamp,
                new JwtIssuerValidator(properties.issuer()), new JwtContractValidator(properties, clock)));
        return decoder;
    }

    /**
     * Convierte roles explícitos del token a autoridades ROLE_ de Spring Security.
     * @return conversor de roles sin utilizar scopes como permisos de negocio
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");
        roles.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(roles);
        return converter;
    }
}
