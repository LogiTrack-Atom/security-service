package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.bootstrap.AdminBootstrapRunner;
import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.enums.Rol;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.*;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

/**
 * Valida API, filtros de seguridad y commits reales contra MySQL separado.
 *
 * <p>No utiliza transacciones de prueba que oculten errores de commit.
 * Testcontainers administra el contenedor y elimina sus recursos temporales.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 */
class RegistroUsuariosIT extends MySqlIntegrationSupport {
    /** El alta publica identidad, persiste auditoría y almacena únicamente el hash. */
    @Test
    void registraClienteConPersistenciaReal() throws Exception {
        String password = UUID.randomUUID().toString();
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json(" Ana@EXAMPLE.COM ", password)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id", not(emptyOrNullString())))
                .andExpect(jsonPath("$.email").value("ana@example.com"))
                .andExpect(jsonPath("$.roles", contains("CLIENTE")))
                .andExpect(jsonPath("$.createdAt", not(emptyOrNullString())))
                .andExpect(jsonPath("$.updatedAt", not(emptyOrNullString())))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(header().doesNotExist("Set-Cookie"));
        var persisted = repository.findByEmail("ana@example.com").orElseThrow();
        assertThat(persisted.getId()).isNotNull();
        assertThat(persisted.getCreatedAt()).isNotNull();
        assertThat(persisted.getPasswordHash()).doesNotContain(password);
        assertThat(encoder.matches(password, persisted.getPasswordHash())).isTrue();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM usuarios", Integer.class)).isOne();
    }

    /** Las variantes de mayúsculas y espacios no crean cuentas adicionales. */
    @Test
    void duplicadoDevuelve409SinReemplazarHash() throws Exception {
        String originalPassword = UUID.randomUUID().toString();
        service.registrar(new RegistroRequest("ana@example.com", originalPassword));
        String originalHash = repository.findByEmail("ana@example.com").orElseThrow().getPasswordHash();
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json(" ANA@EXAMPLE.COM ", UUID.randomUUID().toString())))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.detalles", empty()));
        assertThat(repository.count()).isOne();
        assertThat(repository.findByEmail("ana@example.com").orElseThrow().getPasswordHash()).isEqualTo(originalHash);
    }

    /** Rechaza campos capaces de expresar rol o pertenencia antes de persistir. */
    @ParameterizedTest
    @ValueSource(strings = {"rol", "roles", "usuarioId", "clienteId", "repartidorId"})
    void rechazaOverposting(String field) throws Exception {
        String password = UUID.randomUUID().toString();
        String body = mapper.writeValueAsString(Map.of("email", "ana@example.com", "password", password, field, "ADMIN"));
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400))
                .andExpect(content().string(not(containsString(password))));
        assertThat(repository.count()).isZero();
    }

    /** Una contraseña fuera de rango produce 400 y nunca se devuelve en el error. */
    @ParameterizedTest
    @ValueSource(strings = {"corta", "", "ñññññññññññññññññññññññññññññññññññññ"})
    void rechazaContrasenasInvalidas(String password) throws Exception {
        var response = mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("ana@example.com", password)))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.detalles", not(empty())))
                .andReturn().getResponse();
        if (!password.isEmpty()) assertThat(response.getContentAsString()).doesNotContain(password);
        assertThat(repository.count()).isZero();
    }

    /** Un cuerpo malformado no expone fragmentos de contraseña. */
    @Test
    void rechazaJsonMalformado() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ana@example.com\",\"password\":\"fragmento-confidencial"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("fragmento-confidencial"))));
    }

    /** Un tipo de contenido incorrecto conserva el error HTTP 415. */
    @Test
    void rechazaContenidoNoJson() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.TEXT_PLAIN).content("datos"))
                .andExpect(status().isUnsupportedMediaType()).andExpect(jsonPath("$.status").value(415));
        assertThat(repository.count()).isZero();
    }

    /** Una identidad de prueba tampoco habilita las rutas denegadas en esta etapa. */
    @Test
    void denegacionAutenticadaMantieneApiError() throws Exception {
        mvc.perform(get("/api/v1/usuarios").with(user("operador").roles("ADMIN")))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.mensaje").value("Acceso denegado."));
    }

    /** El esquema impide persistir roles ajenos al conjunto del dominio. */
    @Test
    void esquemaRechazaRolDesconocido() {
        service.registrar(new RegistroRequest("ana@example.com", UUID.randomUUID().toString()));
        String hash = repository.findByEmail("ana@example.com").orElseThrow().getPasswordHash();
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO usuarios(id,email,password_hash,rol,created_at,updated_at)
                VALUES(UUID_TO_BIN(?),?,?,?,CURRENT_TIMESTAMP(6),CURRENT_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), "otro@example.com", hash, "ROL_INVALIDO"))
                .isInstanceOf(DataAccessException.class);
        assertThat(repository.count()).isOne();
    }

    /** Las rutas de negocio y diagnóstico protegidas no admiten acceso anónimo ni sesiones. */
    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/usuarios", "/api/v1/auth/me", "/actuator/env"})
    void deniegaRutasNoHabilitadas(String path) throws Exception {
        mvc.perform(get(path)).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.mensaje").value("Autenticación requerida."))
                .andExpect(jsonPath("$.detalles", empty()))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    /** La restricción de MySQL impide dos commits para el mismo correo. */
    @Test
    void registroConcurrenteMantieneUnaSolaCuenta() throws Exception {
        var start = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(() -> registrarConcurrente(start));
            var second = executor.submit(() -> registrarConcurrente(start));
            start.countDown();
            assertThat(java.util.List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(201, 409);
        }
        assertThat(repository.count()).isOne();
        assertThat(repository.findByEmail("race@example.com").orElseThrow().getRol()).isEqualTo(Rol.CLIENTE);
    }

    /** Repetir el bootstrap conserva UUID, hash y fechas de la primera cuenta ADMIN. */
    @Test
    void bootstrapEsIdempotenteEnMySql() {
        String password = UUID.randomUUID().toString();
        service.asegurarAdministradorInicial(new RegistroRequest(" ADMIN@example.com ", password));
        var first = repository.findByEmail("admin@example.com").orElseThrow();
        service.asegurarAdministradorInicial(new RegistroRequest("admin@example.com", UUID.randomUUID().toString()));
        var second = repository.findByEmail("admin@example.com").orElseThrow();
        assertThat(repository.count()).isOne();
        assertThat(second.getId()).isEqualTo(first.getId());
        assertThat(second.getPasswordHash()).isEqualTo(first.getPasswordHash());
        assertThat(second.getUpdatedAt()).isEqualTo(first.getUpdatedAt());
        assertThat(second.getRol()).isEqualTo(Rol.ADMIN);
        assertThat(encoder.matches(password, second.getPasswordHash())).isTrue();
    }

    /** Una cuenta CLIENTE existente no cambia de rol mediante bootstrap. */
    @Test
    void bootstrapNoPromueveCliente() {
        service.registrar(new RegistroRequest("ana@example.com", UUID.randomUUID().toString()));
        var before = repository.findByEmail("ana@example.com").orElseThrow();
        assertThatThrownBy(() -> service.asegurarAdministradorInicial(
                new RegistroRequest("ana@example.com", UUID.randomUUID().toString())))
                .isInstanceOf(IllegalStateException.class);
        var after = repository.findByEmail("ana@example.com").orElseThrow();
        assertThat(after.getRol()).isEqualTo(Rol.CLIENTE);
        assertThat(after.getPasswordHash()).isEqualTo(before.getPasswordHash());
    }

    /** El bootstrap está deshabilitado por defecto y la cuenta MySQL no es root. */
    @Test
    void aislamientoDeBaseYBootstrapDeshabilitado() {
        assertThat(context.getBeansOfType(AdminBootstrapRunner.class)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT CURRENT_USER()", String.class)).startsWith("security_app@");
        assertThatThrownBy(() -> jdbc.queryForList("SELECT User FROM mysql.user"))
                .isInstanceOf(DataAccessException.class);
    }

    /** Ejecuta una solicitud concurrente sin ocultar sus commits mediante rollback de prueba. */
    private int registrarConcurrente(CountDownLatch start) throws Exception {
        if (!start.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("No comenzó la prueba concurrente.");
        return mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("race@example.com", UUID.randomUUID().toString())))
                .andReturn().getResponse().getStatus();
    }

    /** Construye JSON de prueba mediante el serializador real. */
    private String json(String email, String password) {
        return mapper.writeValueAsString(Map.of("email", email, "password", password));
    }
}
