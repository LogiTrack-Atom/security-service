package com.logitrack_atom.security_service.security;

import com.logitrack_atom.security_service.support.TestRsaKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.assertj.core.api.Assertions.*;

/**
 * Verifica carga local, tamaño RSA, correspondencia y fallos sin material privado en errores.
 *
 * @author MaxDz
 * @version 0.2.0
 */
class RsaKeyLoaderTest {
    @TempDir Path directory;

    /** El par PEM temporal se carga sin modificarlo. */
    @Test
    void cargaParValido() {
        var keys = new RsaKeyLoader().cargar(TestRsaKeys.privateResource(), TestRsaKeys.publicResource());
        assertThat(keys.getPublic().getEncoded()).isEqualTo(TestRsaKeys.pair().getPublic().getEncoded());
    }

    /** La clave pública de otro par no puede usarse para verificar al emisor. */
    @Test
    void rechazaParInconsistente() throws Exception {
        Path other = directory.resolve("other.pem");
        TestRsaKeys.escribir(other, "PUBLIC KEY", TestRsaKeys.generar(2048).getPublic().getEncoded());
        assertThatThrownBy(() -> new RsaKeyLoader().cargar(TestRsaKeys.privateResource(), new FileSystemResource(other)))
                .isInstanceOf(IllegalStateException.class);
    }

    /** Un par RSA pequeño no habilita el arranque. */
    @Test
    void rechazaRsaDebil() throws Exception {
        var keys = TestRsaKeys.generar(1024);
        Path privatePath = directory.resolve("weak-private.pem");
        Path publicPath = directory.resolve("weak-public.pem");
        TestRsaKeys.escribir(privatePath, "PRIVATE KEY", keys.getPrivate().getEncoded());
        TestRsaKeys.escribir(publicPath, "PUBLIC KEY", keys.getPublic().getEncoded());
        assertThatThrownBy(() -> new RsaKeyLoader().cargar(new FileSystemResource(privatePath), new FileSystemResource(publicPath)))
                .isInstanceOf(IllegalStateException.class);
    }

    /** Un PEM inválido no se incorpora al error que registra Spring al arrancar. */
    @Test
    void ocultaContenidoDeArchivoInvalido() throws Exception {
        Path invalid = directory.resolve("invalid.pem");
        Files.writeString(invalid, "contenido-de-prueba-no-publicable");
        assertThatThrownBy(() -> new RsaKeyLoader().cargar(new FileSystemResource(invalid), TestRsaKeys.publicResource()))
                .isInstanceOf(IllegalStateException.class).hasMessageNotContaining("contenido-de-prueba-no-publicable");
    }

    /** No consulta HTTP para resolver las claves del servicio. */
    @Test
    void rechazaUrlRemotaAntesDeLeerla() throws Exception {
        assertThatThrownBy(() -> new RsaKeyLoader().cargar(new UrlResource("https://example.com/private.pem"), TestRsaKeys.publicResource()))
                .isInstanceOf(IllegalStateException.class);
    }
}
