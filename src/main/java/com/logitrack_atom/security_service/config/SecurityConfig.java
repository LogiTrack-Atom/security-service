package com.logitrack_atom.security_service.config;

import com.logitrack_atom.security_service.dto.response.ApiError;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
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
 * Define la frontera stateless de registro, identidad JWT y administración.
 *
 * <p>La API no usa sesiones, formularios ni autenticación por cookies. Las rutas
 * administrativas exigen ADMIN y las rutas no declaradas se deniegan.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
@Configuration
public class SecurityConfig {
    /** Crea la configuración de seguridad HTTP. */
    public SecurityConfig() { }

    /**
     * Aplica acceso público, autenticado o ADMIN según la operación declarada.
     * @param http constructor de seguridad web
     * @param mapper serializador JSON de la aplicación
     * @param decoder validador local de JWT
     * @param converter conversor de roles de negocio
     * @return cadena de filtros stateless
     * @throws Exception si no puede construirse la configuración de seguridad
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectMapper mapper,
                                                   JwtDecoder decoder, JwtAuthenticationConverter converter) throws Exception {
        AuthenticationEntryPoint unauthorized = (request, response, ex) -> {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            escribirError(response, mapper, HttpStatus.UNAUTHORIZED, "Autenticación requerida.");
        };
        AccessDeniedHandler forbidden = (request, response, ex) ->
                escribirError(response, mapper, HttpStatus.FORBIDDEN, "Acceso denegado.");
        return http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/me").hasAnyRole("ADMIN", "CLIENTE", "REPARTIDOR")
                        .requestMatchers(HttpMethod.POST, "/api/v1/usuarios").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/v1/usuarios/{id}").hasRole("ADMIN")
                        .anyRequest().denyAll())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(unauthorized).accessDeniedHandler(forbidden))
                .oauth2ResourceServer(resource -> resource
                        .authenticationEntryPoint(unauthorized).accessDeniedHandler(forbidden)
                        .jwt(jwt -> jwt.decoder(decoder).jwtAuthenticationConverter(converter)))
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
