package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.response.ApiError;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.support.TestRsaKeys;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Verifica login, firma y perfil mediante HTTP, filtros reales y MySQL aislado.
 *
 * @author MaxDz
 * @version 0.2.0
 */
class AutenticacionJwtIT extends MySqlIntegrationSupport {
    /** El flujo completo conserva el hash y emite un token con el contrato de 900 segundos. */
    @Test
    void registroLoginYPerfilPropio() throws Exception {
        String password = UUID.randomUUID().toString();
        var created = service.registrar(new RegistroRequest("ana@example.com", password));
        var before = repository.findById(created.id()).orElseThrow();
        var token = login(" ANA@example.com ", password);
        var jwt = decoder.decode(token.accessToken());
        assertThat(token.expiresIn()).isEqualTo(900);
        assertThat(token.tokenType()).isEqualTo("Bearer");
        assertThat(jwt.getSubject()).isEqualTo(created.id().toString());
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("CLIENTE");
        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(Duration.ofSeconds(900));
        assertThat(jwt.getClaims()).doesNotContainKeys("password", "passwordHash", "clienteId", "repartidorId");
        mvc.perform(get("/api/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(created.id().toString()))
                .andExpect(jsonPath("$.email").value("ana@example.com"))
                .andExpect(jsonPath("$.roles[0]").value("CLIENTE"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
        var after = repository.findById(created.id()).orElseThrow();
        assertThat(after.getPasswordHash()).isEqualTo(before.getPasswordHash());
        assertThat(after.getUpdatedAt()).isEqualTo(before.getUpdatedAt());
    }

    /** Cuenta inexistente y contraseña incorrecta producen la misma denegación pública. */
    @Test
    void credencialesInvalidasTienenRespuestaUniforme() throws Exception {
        service.registrar(new RegistroRequest("ana@example.com", UUID.randomUUID().toString()));
        ApiError first = errorLogin("ana@example.com", "incorrecta");
        ApiError second = errorLogin("nadie@example.com", "incorrecta");
        assertThat(first.status()).isEqualTo(401);
        assertThat(first.mensaje()).isEqualTo("Credenciales inválidas.").isEqualTo(second.mensaje());
        assertThat(first.error()).isEqualTo(second.error());
        assertThat(first.detalles()).isEmpty();
        assertThat(second.detalles()).isEmpty();
        assertThat(repository.count()).isOne();
    }

    /** Cada rol admitido puede consultar su perfil, con roles derivados de la base. */
    @ParameterizedTest
    @EnumSource(Rol.class)
    void emiteRolesPersistidosYAutorizaMe(Rol rol) throws Exception {
        String password = UUID.randomUUID().toString();
        var usuario = repository.saveAndFlush(new Usuario("operador@example.com", encoder.encode(password), rol));
        var token = login(usuario.getEmail(), password);
        assertThat(decoder.decode(token.accessToken()).getClaimAsStringList("roles")).containsExactly(rol.name());
        mvc.perform(get("/api/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(usuario.getId().toString()));
    }

    /** Un parámetro de usuario ajeno no sustituye el sub del JWT autenticado. */
    @Test
    void meNoPermiteElegirOtraIdentidad() throws Exception {
        String password = UUID.randomUUID().toString();
        var own = service.registrar(new RegistroRequest("propio@example.com", password));
        var other = service.registrar(new RegistroRequest("otro@example.com", UUID.randomUUID().toString()));
        var token = login("propio@example.com", password);
        mvc.perform(get("/api/v1/auth/me").param("usuarioId", other.id().toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(own.id().toString()));
    }

    /** Los filtros rechazan tokens inválidos sin delegarlos al perfil ni devolver el token. */
    @ParameterizedTest
    @ValueSource(strings = {"vencido", "firma-ajena", "emisor", "audiencia", "sub", "rol", "sin-exp", "alterado", "HS256", "none"})
    void jwtInvalidoProduce401(String caso) throws Exception {
        var user = service.registrar(new RegistroRequest("ana@example.com", UUID.randomUUID().toString()));
        String token = invalido(caso, user.id());
        mvc.perform(get("/api/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.mensaje").value("Autenticación requerida."))
                .andExpect(content().string(org.hamcrest.Matchers.not(containsString(token))));
    }

    /** Una firma válida de una cuenta retirada no permite consultar una cuenta inexistente. */
    @Test
    void perfilDeUsuarioRetiradoProduce401() throws Exception {
        String token = firmar(claims(UUID.randomUUID()).build(), TestRsaKeys.pair().getPrivate());
        mvc.perform(get("/api/v1/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.mensaje").value("Credenciales inválidas."));
    }

    /** El login también rechaza campos con los que se intente elegir el rol o la identidad. */
    @ParameterizedTest
    @ValueSource(strings = {"roles", "rol", "sub", "usuarioId", "clienteId", "repartidorId"})
    void loginNoAdmiteClaimsDelCliente(String field) throws Exception {
        String body = mapper.writeValueAsString(Map.of("email", "ana@example.com", "password", "password-test-123", field, "ADMIN"));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
    }

    /** Los tokens en la URL no sustituyen la cabecera Authorization. */
    @Test
    void noAceptaTokenEnQueryString() throws Exception {
        String password = UUID.randomUUID().toString();
        service.registrar(new RegistroRequest("ana@example.com", password));
        String token = login("ana@example.com", password).accessToken();
        mvc.perform(get("/api/v1/auth/me").param("access_token", token)).andExpect(status().isUnauthorized());
    }

    /** Ejecuta login y comprueba las cabeceras que evitan cachear el token. */
    private TokenResponse login(String email, String password) throws Exception {
        var response = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("email", email, "password", password))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn().getResponse();
        return mapper.readValue(response.getContentAsString(), TokenResponse.class);
    }

    /** Obtiene el error público de una autenticación rechazada. */
    private ApiError errorLogin(String email, String password) throws Exception {
        var response = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("email", email, "password", password))))
                .andExpect(status().isUnauthorized()).andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andReturn().getResponse();
        return mapper.readValue(response.getContentAsString(), ApiError.class);
    }

    /** Prepara claims válidos con fechas actuales para atravesar los filtros reales. */
    private JWTClaimsSet.Builder claims(UUID userId) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder().issuer("logitrack-security").audience("logitrack-api")
                .subject(userId.toString()).claim("roles", List.of("CLIENTE"))
                .issueTime(Date.from(now)).notBeforeTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(900)));
    }

    /** Construye un fallo controlado sin utilizar claves ni usuarios reales del equipo. */
    private String invalido(String caso, UUID userId) throws Exception {
        var builder = claims(userId);
        Instant now = Instant.now();
        switch (caso) {
            case "vencido" -> builder.issueTime(Date.from(now.minusSeconds(1000)))
                    .notBeforeTime(Date.from(now.minusSeconds(1000))).expirationTime(Date.from(now.minusSeconds(100)));
            case "emisor" -> builder.issuer("otro-emisor");
            case "audiencia" -> builder.audience("otra-api");
            case "sub" -> builder.subject("identidad-invalida");
            case "rol" -> builder.claim("roles", List.of("SUPER_ADMIN"));
            case "sin-exp" -> builder.expirationTime(null);
            default -> { }
        }
        var claims = builder.build();
        if (caso.equals("none")) return new PlainJWT(claims).serialize();
        if (caso.equals("HS256")) {
            var token = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            token.sign(new MACSigner(TestRsaKeys.pair().getPublic().getEncoded()));
            return token.serialize();
        }
        var key = caso.equals("firma-ajena") ? TestRsaKeys.generar(2048).getPrivate() : TestRsaKeys.pair().getPrivate();
        String token = firmar(claims, key);
        if (caso.equals("alterado")) {
            String[] parts = token.split("\\.");
            parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    claims(userId).claim("roles", List.of("ADMIN")).build().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return String.join(".", parts);
        }
        return token;
    }

    /** Firma claims de prueba con el algoritmo acordado. */
    private String firmar(JWTClaimsSet claims, java.security.PrivateKey key) throws Exception {
        var token = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        token.sign(new RSASSASigner(key));
        return token.serialize();
    }
}
