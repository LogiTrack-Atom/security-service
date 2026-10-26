package com.logitrack_atom.security_service.config;

import com.logitrack_atom.security_service.dto.response.ApiError;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

/**
 * Define la frontera de seguridad de la etapa de registro público.
 *
 * <p>La API no usa sesiones, formularios ni autenticación por cookies. Las rutas
 * restantes permanecen denegadas hasta incorporar JWT en la siguiente issue.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 */
@Configuration
public class SecurityConfig {
    /** Crea la configuración de seguridad HTTP. */
    public SecurityConfig() { }

    /**
     * Habilita exclusivamente el registro y mantiene errores coherentes con ApiError.
     * @param http constructor de seguridad web
     * @param mapper serializador JSON de la aplicación
     * @return cadena de filtros stateless
     * @throws Exception si no puede construirse la configuración de seguridad
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectMapper mapper) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                        .anyRequest().denyAll())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, ex) ->
                                escribirError(response, mapper, HttpStatus.UNAUTHORIZED, "Autenticación requerida."))
                        .accessDeniedHandler((request, response, ex) ->
                                escribirError(response, mapper, HttpStatus.FORBIDDEN, "Acceso denegado.")))
                .build();
    }

    /**
     * Serializa una denegación sin detalles de las credenciales recibidas.
     * @param response respuesta HTTP
     * @param mapper serializador JSON
     * @param status estado de la denegación
     * @param mensaje descripción segura
     * @throws IOException si no se puede escribir la respuesta
     */
    private void escribirError(HttpServletResponse response, ObjectMapper mapper,
                               HttpStatus status, String mensaje) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        mapper.writeValue(response.getOutputStream(), new ApiError(
                Instant.now(), status.value(), status.getReasonPhrase(), mensaje, List.of()));
    }
}
