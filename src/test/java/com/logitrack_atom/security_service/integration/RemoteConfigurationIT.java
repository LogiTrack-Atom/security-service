package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.SecurityServiceApplication;
import com.logitrack_atom.security_service.config.ConfigMarkerProperties;
import com.logitrack_atom.security_service.config.JwtProperties;
import com.logitrack_atom.security_service.support.ConfigServerFixture;
import com.logitrack_atom.security_service.support.TestRsaKeys;
import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestClient;
import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import static org.assertj.core.api.Assertions.*;

/**
 * Comprueba dev/prod contra Config Server real, Git temporal y MySQL aislado.
 *
 * <p>El marcador, puerto, base, logging y JWT se leen del origen remoto.
 * Los secretos se aportan al cliente y nunca se escriben en el repositorio de prueba.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
class RemoteConfigurationIT {
    @TempDir static Path temporary;
    private static ConfigurableApplicationContext server;
    private static String baseUrl;

    /** Prepara una rama develop con dos configuraciones y arranca el servidor real. */
    @BeforeAll
    static void startServer() throws Exception {
        Path repository = Files.createDirectory(temporary.resolve("repository"));
        for (String profile : new String[]{"dev", "prod"}) {
            try (var input = new ClassPathResource("config-repository/security-service-" + profile + ".yaml").getInputStream()) {
                Files.copy(input, repository.resolve("security-service-" + profile + ".yaml"));
            }
        }
        try (Git git = Git.init().setDirectory(repository.toFile()).setInitialBranch("develop").call()) {
            git.add().addFilepattern(".").call();
            git.commit().setAuthor("Pruebas LogiTrack", "pruebas@example.com")
                    .setCommitter("Pruebas LogiTrack", "pruebas@example.com").setMessage("Configuración de prueba dev/prod").call();
        }
        server = ConfigServerFixture.start(repository, temporary.resolve("clone"));
        baseUrl = "http://127.0.0.1:" + server.getEnvironment().getProperty("local.server.port");
    }

    /** Cierra el servidor y sus recursos antes de retirar los directorios temporales. */
    @AfterAll
    static void stopServer() { if (server != null) server.close(); }

    /** Ambos ambientes enlazan propiedades remotas diferenciadas sin desactivar compatibilidad. */
    @ParameterizedTest
    @ValueSource(strings = {"dev", "prod"})
    void consumesRemoteProperties(String profile) throws Exception {
        try (var client = client(profile, Map.of())) {
            assertThat(client.getBean(ConfigMarkerProperties.class).marker()).isEqualTo("security-" + profile);
            var environment = client.getEnvironment();
            assertThat(environment.getPropertySources().stream().anyMatch(source -> source.getName().contains("configserver:"))).isTrue();
            assertThat(environment.getProperty("spring.application.name")).isEqualTo("security-service");
            assertThat(environment.getProperty("server.port")).isEqualTo("0");
            assertThat(environment.getProperty("logging.level.com.logitrack_atom")).isEqualTo(profile.equals("dev") ? "INFO" : "WARN");
            assertThat(client.getBean(JwtProperties.class).accessTokenTtl()).isEqualTo(Duration.ofMinutes(profile.equals("dev") ? 15 : 10));
            assertThat(environment.getProperty("spring.cloud.compatibility-verifier.enabled", Boolean.class, true)).isTrue();
            try (var connection = client.getBean(DataSource.class).getConnection()) {
                assertThat(connection.getCatalog()).isEqualTo("security_db");
                assertThat(connection.getMetaData().getUserName()).startsWith("security_app");
            }
            String url = "http://127.0.0.1:" + environment.getProperty("local.server.port");
            assertThat(RestClient.create().get().uri(url + "/actuator/health").retrieve().body(String.class))
                    .contains("\"status\":\"UP\"").doesNotContain("components", "details", "password", "marker");
            org.springframework.http.HttpStatusCode denied = RestClient.create().get().uri(url + "/actuator/env")
                    .exchange((request, response) -> response.getStatusCode());
            assertThat(denied).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    /** El servidor publica placeholders, incluso si su proceso tiene un valor homónimo. */
    @Test
    void serverDoesNotResolveClientSecrets() {
        String response = RestClient.create().get().uri(baseUrl + "/security-service/dev/develop").retrieve().body(String.class);
        assertThat(response).contains("${DB_PASSWORD}", "${JWT_PRIVATE_KEY_LOCATION}")
                .doesNotContain("valor-del-servidor-que-no-debe-publicarse");
    }

    /** La ausencia de claves externas impide completar un arranque con configuración remota. */
    @Test
    void missingKeyStopsStartup() {
        assertThatThrownBy(() -> client("dev", Map.of("JWT_PRIVATE_KEY_LOCATION", temporary.resolve("missing.pem").toUri().toString())))
                .hasStackTraceContaining("No se pudieron cargar las claves RSA locales");
    }

    /** La ausencia de contraseña de aplicación no utiliza credenciales alternativas. */
    @Test
    void missingDatabasePasswordStopsStartup() {
        assertThatThrownBy(() -> client("dev", Map.of("DB_PASSWORD", "")))
                .hasStackTraceContaining("JDBC metadata");
    }

    /** Un Config Server inaccesible rechaza el arranque obligatorio sin fallback local. */
    @Test
    void unavailableServerStopsStartup() throws Exception {
        int unused;
        try (var socket = new java.net.ServerSocket(0)) { unused = socket.getLocalPort(); }
        assertThatThrownBy(() -> client("prod", Map.of("CONFIG_SERVER_URL", "http://127.0.0.1:" + unused)))
                .hasStackTraceContaining("Could not locate PropertySource");
    }

    /**
     * Inicia el cliente de producción con secretos efímeros y un perfil remoto explícito.
     * @param profile ambiente solicitado
     * @param overrides alteraciones controladas para casos negativos
     * @return contexto del cliente que la prueba debe cerrar
     * @throws Exception si no se pueden resolver los recursos de clave de prueba
     */
    private ConfigurableApplicationContext client(String profile, Map<String, Object> overrides) throws Exception {
        Map<String, Object> external = new HashMap<>(MySqlIntegrationSupport.databaseProperties());
        external.put("CONFIG_SERVER_URL", baseUrl);
        external.put("CONFIG_LABEL", "develop");
        external.put("SECURITY_SERVER_PORT", "0");
        external.put("JWT_PRIVATE_KEY_LOCATION", TestRsaKeys.privateResource().getFile().toPath().toUri().toString());
        external.put("JWT_PUBLIC_KEY_LOCATION", TestRsaKeys.publicResource().getFile().toPath().toUri().toString());
        external.putAll(overrides);
        return new SpringApplicationBuilder(SecurityServiceApplication.class)
                .properties(external)
                .run("--spring.profiles.active=" + profile, "--spring.main.banner-mode=off",
                        "--spring.cloud.config.enabled=true");
    }
}
