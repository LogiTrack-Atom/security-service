package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.controller.BrowserSessionController;
import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import jakarta.servlet.http.Cookie;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Prueba cookies, CSRF y rotación mediante filtros HTTP, transacciones y MySQL reales. */
@TestPropertySource(properties = "logitrack.session.origin=https://ui.example.test")
class BrowserSessionIT extends MySqlIntegrationSupport {
    private static final String PATH = "/api/v1/auth/session";
    private static final String ORIGIN = "https://ui.example.test";
    private static final String PASSWORD = UUID.randomUUID().toString();

    /** Registra una cuenta ficticia e inicia una sesión HTTP protegida. */
    private MvcResult login() throws Exception {
        service.registrar(new RegistroRequest("session@example.test", PASSWORD));
        return mvc.perform(post(PATH).header("Origin", ORIGIN).header("X-LogiTrack-Session", "1")
                .contentType("application/json").content(mapper.writeValueAsString(Map.of("email", "session@example.test", "password", PASSWORD))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.refresh").doesNotExist()).andReturn();
    }
    /** @param result respuesta con Set-Cookie @return valor opaco sin atributos */
    private String value(MvcResult result) { return result.getResponse().getHeader("Set-Cookie").split(";", 2)[0].split("=", 2)[1]; }
    /** @param token credencial ficticia @return resultado de renovación real */
    private MvcResult refresh(String token) throws Exception {
        return mvc.perform(post(PATH + "/refresh").header("Origin", ORIGIN).header("X-LogiTrack-Session", "1")
                .cookie(new Cookie(BrowserSessionController.COOKIE, token))).andReturn();
    }

    /** La cookie se protege; la BD no contiene el secreto y el token solo se consume una vez. */
    @Test void rotaSinPersistirCredencialesYRevocaReplay() throws Exception {
        var initial = login(); String old = value(initial);
        assertThat(initial.getResponse().getHeader("Set-Cookie")).contains("HttpOnly", "Secure", "SameSite=Strict", "Path=/").doesNotContain("Domain=");
        assertThat(initial.getResponse().getHeader("Cache-Control")).contains("no-store");
        var row = jdbc.queryForMap("select token_hash, expires_at from refresh_sessions");
        assertThat(row.get("token_hash").toString()).hasSize(64).doesNotContain(old);
        var next = refresh(old); assertThat(next.getResponse().getStatus()).isEqualTo(200);
        String current = value(next); assertThat(current).isNotEqualTo(old);
        assertThat(jdbc.queryForObject("select expires_at from refresh_sessions", java.sql.Timestamp.class)).isEqualTo(row.get("expires_at"));
        assertThat(refresh(old).getResponse().getStatus()).isEqualTo(401);
        assertThat(jdbc.queryForObject("select revoked from refresh_sessions", Boolean.class)).isTrue();
        assertThat(refresh(current).getResponse().getStatus()).isEqualTo(401);
    }

    /** Dos renovaciones simultáneas no producen dos ramas válidas de la familia. */
    @Test void concurrenciaSeSerializaEnMysql() throws Exception {
        String old = value(login());
        try (var pool = Executors.newFixedThreadPool(2)) {
            var start = new CountDownLatch(1);
            Callable<Integer> action = () -> { start.await(); return refresh(old).getResponse().getStatus(); };
            var a = pool.submit(action); var b = pool.submit(action); start.countDown();
            assertThat(List.of(a.get(20, TimeUnit.SECONDS), b.get(20, TimeUnit.SECONDS))).containsExactlyInAnyOrder(200, 401);
        }
        assertThat(jdbc.queryForObject("select revoked from refresh_sessions", Boolean.class)).isTrue();
    }

    /** Vencimiento absoluto y logout impiden volver a renovar sin ampliar el JWT copiado. */
    @Test void logoutYVencimientoRevocanRenovacion() throws Exception {
        String token = value(login());
        mvc.perform(post(PATH + "/logout").header("Origin", ORIGIN).header("X-LogiTrack-Session", "1")
                .cookie(new Cookie(BrowserSessionController.COOKIE, token)))
                .andExpect(status().isNoContent()).andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("Max-Age=0")));
        assertThat(refresh(token).getResponse().getStatus()).isEqualTo(401);
        jdbc.update("update refresh_sessions set revoked=false, expires_at=timestampadd(second,-1,current_timestamp(6))");
        assertThat(refresh(token).getResponse().getStatus()).isEqualTo(401);
    }

    /** Conocer un selector sin su secreto no permite renovar ni revocar una sesión ajena. */
    @Test void secretoIncorrectoNoRevocaFamiliaValida() throws Exception {
        String token = value(login());
        String wrong = token.substring(0, 37) + "A".repeat(43);
        assertThat(refresh(wrong).getResponse().getStatus()).isEqualTo(401);
        assertThat(jdbc.queryForObject("select revoked from refresh_sessions", Boolean.class)).isFalse();
        assertThat(refresh(token).getResponse().getStatus()).isEqualTo(200);
    }

    /** Los endpoints de cookie no aceptan formularios/cabeceras simples ni orígenes ajenos. */
    @ParameterizedTest @ValueSource(strings = {"https://evil.example.test", "null", ""})
    void csrfRechazaOrigenAjenoSinMutar(String origin) throws Exception {
        String token = value(login());
        for (String suffix : List.of("/refresh", "/logout")) {
            mvc.perform(post(PATH + suffix).header("Origin", origin).header("X-LogiTrack-Session", "1")
                    .cookie(new Cookie(BrowserSessionController.COOKIE, token)))
                    .andExpect(status().isForbidden()).andExpect(header().doesNotExist("Set-Cookie"));
            mvc.perform(post(PATH + suffix).header("Origin", ORIGIN)
                    .cookie(new Cookie(BrowserSessionController.COOKIE, token))).andExpect(status().isForbidden());
        }
        assertThat(jdbc.queryForObject("select revoked from refresh_sessions", Boolean.class)).isFalse();
        assertThat(jdbc.queryForObject("select count(*) from consumed_refresh_tokens", Integer.class)).isZero();
    }

    /** Cookies ambiguas no seleccionan una identidad por orden. */
    @Test void cookiesDuplicadasYAusentesNoRenuevan() throws Exception {
        String token = value(login());
        mvc.perform(post(PATH + "/refresh").header("Origin", ORIGIN).header("X-LogiTrack-Session", "1"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(PATH + "/refresh").header("Origin", ORIGIN).header("X-LogiTrack-Session", "1")
                .cookie(new Cookie(BrowserSessionController.COOKIE, token), new Cookie(BrowserSessionController.COOKIE, token)))
                .andExpect(status().isUnauthorized());
    }
}
