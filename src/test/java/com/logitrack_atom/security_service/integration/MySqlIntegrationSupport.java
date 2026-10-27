package com.logitrack_atom.security_service.integration;

import com.logitrack_atom.security_service.repository.UsuarioRepository;
import com.logitrack_atom.security_service.service.UsuarioService;
import com.logitrack_atom.security_service.support.TestRsaKeys;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.UUID;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Comparte MySQL aislado y claves efímeras entre las suites de registro y autenticación.
 *
 * <p>Las llamadas al servicio realizan commits reales. La limpieza comprueba
 * la base de destino antes de modificar exclusivamente los datos de prueba.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
abstract class MySqlIntegrationSupport {
    private static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4.11")
            .withDatabaseName("security_db").withUsername("security_app")
            .withPassword(UUID.randomUUID().toString()).withUrlParam("serverTimezone", "UTC")
            .withCopyFileToContainer(MountableFile.forHostPath(
                    Path.of("docker/mysql/init/001-schema.sql").toAbsolutePath()),
                    "/docker-entrypoint-initdb.d/001-schema.sql");
    static { MYSQL.start(); }

    /** Sustituye base y claves únicamente dentro del contexto de integración. */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("logitrack.bootstrap-admin.enabled", () -> false);
        TestRsaKeys.registrar(registry);
    }

    /**
     * Comparte el contenedor aislado con las pruebas de arranque remoto.
     * @return propiedades de conexión exclusivas de este proceso de pruebas
     */
    static Map<String, Object> databaseProperties() {
        return Map.of("DB_URL", MYSQL.getJdbcUrl(), "DB_USERNAME", MYSQL.getUsername(), "DB_PASSWORD", MYSQL.getPassword());
    }

    /** Frontera HTTP real con filtros de Spring Security. */
    @Autowired protected MockMvc mvc;
    /** Acceso directo al contenedor exclusivo de pruebas. */
    @Autowired protected JdbcTemplate jdbc;
    /** Servicio real de registro. */
    @Autowired protected UsuarioService service;
    /** Repositorio real de cuentas. */
    @Autowired protected UsuarioRepository repository;
    /** Verificador real de contraseña. */
    @Autowired protected PasswordEncoder encoder;
    /** Serializador de la aplicación. */
    @Autowired protected ObjectMapper mapper;
    /** Contexto de arranque real. */
    @Autowired protected ApplicationContext context;
    /** Verificador JWT construido con clave pública local. */
    @Autowired protected JwtDecoder decoder;

    /** Limpia únicamente las cuentas de la base temporal previamente identificada. */
    @BeforeEach
    void limpiar() {
        assertThat(jdbc.queryForObject("SELECT DATABASE()", String.class)).isEqualTo("security_db");
        jdbc.update("DELETE FROM usuarios");
    }
}
