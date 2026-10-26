package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.dto.request.UsuarioCreateRequest;
import com.logitrack_atom.security_service.dto.response.ApiError;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.service.JwtTokenService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Verifica la administración por rol con JWT reales, filtros web y MySQL aislado.
 *
 * <p>Las solicitudes atraviesan la firma y el decoder de producción. No se
 * sustituyen usuarios ni autoridades mediante anotaciones de autenticación simulada.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
class AdministracionUsuariosIT extends MySqlIntegrationSupport {
    @Autowired private JwtTokenService tokens;
    @Autowired private JwtEncoder jwtEncoder;

    /** Un ADMIN crea los tres roles y la nueva cuenta puede iniciar sesión con ese rol. */
    @ParameterizedTest
    @EnumSource(Rol.class)
    void adminCreaCuentaYConsultaSuIdentidad(Rol rol) throws Exception {
        String adminToken = token(Rol.ADMIN);
        String password = "  " + UUID.randomUUID() + "  ";
        var request = new UsuarioCreateRequest("  NUEVO@EXAMPLE.COM ", password, rol);
        var result = mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, adminToken)
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(request)))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.email").value("nuevo@example.com"))
                .andExpect(jsonPath("$.roles[0]").value(rol.name()))
                .andExpect(jsonPath("$.password").doesNotExist()).andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.createdAt").isNotEmpty()).andExpect(jsonPath("$.updatedAt").isNotEmpty())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE)).andReturn();
        var created = mapper.readValue(result.getResponse().getContentAsString(), UsuarioResponse.class);
        assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).isEqualTo("/api/v1/usuarios/" + created.id());
        var persisted = repository.findById(created.id()).orElseThrow();
        assertThat(encoder.matches(password, persisted.getPasswordHash())).isTrue();
        assertThat(persisted.getPasswordHash()).isNotEqualTo(password);
        assertThat(result.getResponse().getContentAsString()).doesNotContain(password, persisted.getPasswordHash());

        mvc.perform(get("/api/v1/usuarios/{id}", created.id()).header(HttpHeaders.AUTHORIZATION, adminToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(created.id().toString()))
                .andExpect(jsonPath("$.roles[0]").value(rol.name()))
                .andExpect(jsonPath("$.password").doesNotExist()).andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")));

        var login = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(new LoginRequest(" NUEVO@example.com ", password))))
                .andExpect(status().isOk()).andReturn();
        var access = mapper.readValue(login.getResponse().getContentAsString(), TokenResponse.class);
        var jwt = decoder.decode(access.accessToken());
        assertThat(jwt.getSubject()).isEqualTo(created.id().toString());
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly(rol.name());
        assertThat(result.getRequest().getSession(false)).isNull();
        assertThat(repository.count()).isEqualTo(2);
    }

    /** Los roles sin privilegios no crean cuentas ni consultan identidades, incluso la propia. */
    @ParameterizedTest
    @EnumSource(value = Rol.class, names = {"CLIENTE", "REPARTIDOR"})
    void rolesSinPermisoReciben403SinPersistir(Rol rol) throws Exception {
        String access = token(rol);
        String ownId = decoder.decode(access.substring(7)).getSubject();
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, access)
                .contentType(MediaType.APPLICATION_JSON).content(cuerpoValido())), 403);
        error(mvc.perform(get("/api/v1/usuarios/{id}", ownId).header(HttpHeaders.AUTHORIZATION, access)), 403);
        error(mvc.perform(get("/api/v1/usuarios/{id}", UUID.randomUUID())
                .header(HttpHeaders.AUTHORIZATION, access)), 403);
        assertThat(repository.count()).isOne();
    }

    /** La falta de token se rechaza antes de validar o ejecutar la operación administrativa. */
    @Test
    void ambasRutasExigenBearer() throws Exception {
        error(mvc.perform(post("/api/v1/usuarios").contentType(MediaType.APPLICATION_JSON).content("{")), 401);
        error(mvc.perform(get("/api/v1/usuarios/{id}", UUID.randomUUID())), 401);
        assertThat(repository.count()).isZero();
    }

    /** Un UUID inexistente devuelve 404 sin causar efectos ni revelar datos internos. */
    @Test
    void adminRecibe404ParaCuentaInexistente() throws Exception {
        error(mvc.perform(get("/api/v1/usuarios/{id}", UUID.randomUUID())
                .header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))), 404);
        assertThat(repository.count()).isOne();
    }

    /** Un identificador no convertible no se trata como un fallo interno. */
    @Test
    void identificadorInvalidoDevuelve400() throws Exception {
        var result = error(mvc.perform(get("/api/v1/usuarios/no-es-un-uuid")
                .header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))), 400);
        assertThat(result.mensaje()).doesNotContain("no-es-un-uuid");
    }

    /** Un alta duplicada no promueve un CLIENTE ni cambia su contraseña o auditoría. */
    @Test
    void correoOcupadoNoPromueveNiReemplazaCuenta() throws Exception {
        String admin = token(Rol.ADMIN);
        var previous = repository.saveAndFlush(new Usuario("cliente@example.com", encoder.encode(UUID.randomUUID().toString()), Rol.CLIENTE));
        String beforeHash = previous.getPasswordHash();
        var beforeDate = repository.findById(previous.getId()).orElseThrow().getUpdatedAt();
        var body = new UsuarioCreateRequest("  CLIENTE@EXAMPLE.COM ", UUID.randomUUID().toString(), Rol.ADMIN);
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, admin)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(body))), 409);
        var after = repository.findById(previous.getId()).orElseThrow();
        assertThat(after.getRol()).isEqualTo(Rol.CLIENTE);
        assertThat(after.getPasswordHash()).isEqualTo(beforeHash);
        assertThat(after.getUpdatedAt()).isEqualTo(beforeDate);
        assertThat(repository.count()).isEqualTo(2);
    }

    /** La política de credenciales del alta administrativa coincide con la del registro. */
    @ParameterizedTest
    @ValueSource(strings = {"email", "password", "multibyte", "rol-ausente", "rol-null"})
    void datosInvalidosNoCreanCuenta(String caso) throws Exception {
        var body = new java.util.HashMap<String, Object>();
        body.put("email", "nuevo@example.com");
        body.put("password", UUID.randomUUID().toString());
        body.put("rol", "REPARTIDOR");
        switch (caso) {
            case "email" -> body.put("email", "correo-invalido");
            case "password" -> body.put("password", "corta");
            case "multibyte" -> body.put("password", "ñ".repeat(37));
            case "rol-ausente" -> body.remove("rol");
            case "rol-null" -> body.put("rol", null);
            default -> throw new AssertionError(caso);
        }
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(body))), 400);
        assertThat(repository.count()).isOne();
    }

    /** No se admiten roles desconocidos, ordinales numéricos ni conjuntos de roles. */
    @ParameterizedTest
    @ValueSource(strings = {"\"SUPERADMIN\"", "\"admin\"", "0", "1", "\"0\"", "[]", "[\"ADMIN\"]", "{}"})
    void contratoDeRolEsEstricto(String rolJson) throws Exception {
        String body = "{\"email\":\"nuevo@example.com\",\"password\":\"password-test-123\",\"rol\":" + rolJson + "}";
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))
                .contentType(MediaType.APPLICATION_JSON).content(body)), 400);
        assertThat(repository.count()).isOne();
    }

    /** Tampoco un ADMIN puede fijar UUID, auditoría o asociaciones mediante el alta de usuario. */
    @ParameterizedTest
    @ValueSource(strings = {"id", "roles", "passwordHash", "usuarioId", "clienteId", "repartidorId", "createdAt", "updatedAt"})
    void camposFueraDelContratoSeRechazan(String campo) throws Exception {
        String body = cuerpoValido().replace("}", ",\"" + campo + "\":\"dato-no-admitido\"}");
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))
                .contentType(MediaType.APPLICATION_JSON).content(body)), 400);
        assertThat(repository.count()).isOne();
    }

    /** El parser mantiene un error genérico ante JSON malformado, vacío o con raíz incorrecta. */
    @ParameterizedTest
    @ValueSource(strings = {"{", "", "null", "[]"})
    void jsonInvalidoProduce400(String body) throws Exception {
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))
                .contentType(MediaType.APPLICATION_JSON).content(body)), 400);
    }

    /** Los métodos y rutas administrativas no declarados permanecen denegados para ADMIN. */
    @Test
    void administracionDeniegaOperacionesNoDeclaradas() throws Exception {
        String admin = token(Rol.ADMIN);
        error(mvc.perform(get("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, admin)), 403);
        error(mvc.perform(delete("/api/v1/usuarios/{id}", UUID.randomUUID())
                .header(HttpHeaders.AUTHORIZATION, admin)), 403);
        error(mvc.perform(put("/api/v1/usuarios/{id}", UUID.randomUUID())
                .header(HttpHeaders.AUTHORIZATION, admin).contentType(MediaType.APPLICATION_JSON).content(cuerpoValido())), 403);
        error(mvc.perform(get("/api/v1/usuarios/otro/extra").header(HttpHeaders.AUTHORIZATION, admin)), 403);
        assertThat(repository.count()).isOne();
    }

    /** Ninguna cookie, sesión anterior, Basic ni token en query reemplaza Authorization Bearer. */
    @Test
    void accesoNoSeConservaEnSesionNiAceptaTransportesAlternativos() throws Exception {
        String admin = token(Rol.ADMIN);
        UUID id = UUID.fromString(decoder.decode(admin.substring(7)).getSubject());
        var result = mvc.perform(get("/api/v1/usuarios/{id}", id).header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(status().isOk()).andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE)).andReturn();
        assertThat(result.getRequest().getSession(false)).isNull();
        error(mvc.perform(get("/api/v1/usuarios/{id}", id).cookie(new Cookie("JSESSIONID", "sesion-inventada"))), 401);
        error(mvc.perform(get("/api/v1/usuarios/{id}", id).param("access_token", admin.substring(7))), 401);
        String basic = Base64.getEncoder().encodeToString("admin:password-test-123".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        error(mvc.perform(get("/api/v1/usuarios/{id}", id).header(HttpHeaders.AUTHORIZATION, "Basic " + basic)), 401);
        error(mvc.perform(get("/api/v1/usuarios/{id}", id)), 401);
    }

    /** Un JWT ADMIN correctamente firmado pero vencido se rechaza en ambos endpoints. */
    @Test
    void tokenAdministrativoVencidoNoPermiteLecturasNiEscrituras() throws Exception {
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer("logitrack-security").audience(List.of("logitrack-api"))
                .subject(UUID.randomUUID().toString()).issuedAt(now.minusSeconds(1000))
                .expiresAt(now.minusSeconds(100)).claim("roles", List.of("ADMIN")).build();
        String expired = "Bearer " + jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, expired)
                .contentType(MediaType.APPLICATION_JSON).content(cuerpoValido())), 401);
        error(mvc.perform(get("/api/v1/usuarios/{id}", UUID.randomUUID()).header(HttpHeaders.AUTHORIZATION, expired)), 401);
        assertThat(repository.count()).isZero();
    }

    /** El contrato de tipo de contenido conserva un error 415 con ApiError. */
    @Test
    void tipoDeContenidoInvalidoProduce415() throws Exception {
        error(mvc.perform(post("/api/v1/usuarios").header(HttpHeaders.AUTHORIZATION, token(Rol.ADMIN))
                .contentType(MediaType.TEXT_PLAIN).content(cuerpoValido())), 415);
    }

    /** Genera una cuenta efímera y un token firmado por el emisor real del servicio. */
    private String token(Rol rol) {
        var usuario = repository.saveAndFlush(new Usuario(UUID.randomUUID() + "@example.com",
                encoder.encode(UUID.randomUUID().toString()), rol));
        return "Bearer " + tokens.emitir(usuario).accessToken();
    }

    /** Construye un alta válida sin identidades fijadas por el cliente. */
    private String cuerpoValido() throws Exception {
        return mapper.writeValueAsString(Map.of("email", "nuevo@example.com", "password", UUID.randomUUID().toString(), "rol", "REPARTIDOR"));
    }

    /** Comprueba el contrato de errores sin contraseña, hash, SQL ni detalles del token. */
    private ApiError error(ResultActions action, int status) throws Exception {
        var result = action.andExpect(status().is(status)).andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(status)).andExpect(jsonPath("$.timestamp").isNotEmpty())
                .andExpect(jsonPath("$.error").isNotEmpty()).andExpect(jsonPath("$.mensaje").isNotEmpty())
                .andExpect(jsonPath("$.detalles").isArray()).andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist()).andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn();
        if (status == 401) assertThat(result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
        var error = mapper.readValue(result.getResponse().getContentAsString(), ApiError.class);
        assertThat(error.mensaje()).doesNotContain("password-test-123", "$2", "SELECT", "INSERT", "Bearer ");
        return error;
    }
}
