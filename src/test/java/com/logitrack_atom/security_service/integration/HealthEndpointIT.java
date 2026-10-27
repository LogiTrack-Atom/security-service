package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.service.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Verifica una salud pública mínima y la denegación de diagnósticos sensibles.
 *
 * @author MaxDz
 * @version 0.2.0
 */
class HealthEndpointIT extends MySqlIntegrationSupport {
    @Autowired private JwtTokenService tokens;

    /** El healthcheck no requiere cuenta ni expone componentes, detalles o configuración. */
    @Test
    void healthShowsOnlyAggregateStatus() throws Exception {
        var result = mvc.perform(get("/actuator/health")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP")).andReturn();
        var body = mapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.has("components")).isFalse();
        assertThat(body.has("details")).isFalse();
        assertThat(body.size()).isBetween(1, 2);
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    /** Los endpoints de configuración y otros diagnósticos no se publican por conocer una ruta. */
    @Test
    void diagnosticsRemainDenied() throws Exception {
        var user = service.registrar(new RegistroRequest("cliente@example.com", UUID.randomUUID().toString()));
        String token = tokens.emitir(repository.findById(user.id()).orElseThrow()).accessToken();
        for (String endpoint : new String[]{"env", "configprops", "beans", "loggers", "heapdump"}) {
            mvc.perform(get("/actuator/" + endpoint)).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401));
            mvc.perform(get("/actuator/" + endpoint).header("Authorization", "Bearer " + token))
                    .andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403));
        }
    }
}
