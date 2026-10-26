package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.exception.CredencialesInvalidasException;
import com.logitrack_atom.security_service.mapper.UsuarioMapper;
import com.logitrack_atom.security_service.repository.UsuarioRepository;
import com.logitrack_atom.security_service.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.Optional;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Verifica autenticación sin base y la consulta de identidad por UUID autenticado.
 *
 * @author MaxDz
 * @version 0.2.0
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    @Mock UsuarioRepository repository;
    @Mock PasswordEncoder encoder;
    @Mock JwtTokenService tokens;
    private AuthService auth;

    /** Prepara el hash ficticio sin realizar trabajo criptográfico en estas unitarias. */
    @BeforeEach
    void preparar() {
        when(encoder.encode(anyString())).thenReturn("hash-ficticio");
        auth = new AuthServiceImpl(repository, encoder, tokens, new UsuarioMapper());
        clearInvocations(encoder);
    }

    /** El emisor recibe la cuenta persistida, nunca roles suministrados por el solicitante. */
    @Test
    void loginEmiteSoloSiCoincideLaContrasena() {
        var usuario = new Usuario("ana@example.com", "hash-real", Rol.CLIENTE);
        when(repository.findByEmail("ana@example.com")).thenReturn(Optional.of(usuario));
        when(encoder.matches("password-test-123", "hash-real")).thenReturn(true);
        when(tokens.emitir(usuario)).thenReturn(new TokenResponse("token-de-prueba", "Bearer", 900));
        assertThat(auth.autenticar(new LoginRequest(" ANA@example.com ", "password-test-123")).expiresIn()).isEqualTo(900);
        verify(tokens).emitir(usuario);
    }

    /** Una contraseña incorrecta no produce tokens. */
    @Test
    void rechazaPasswordIncorrecta() {
        when(repository.findByEmail("ana@example.com"))
                .thenReturn(Optional.of(new Usuario("ana@example.com", "hash-real", Rol.CLIENTE)));
        assertThatThrownBy(() -> auth.autenticar(new LoginRequest("ana@example.com", "incorrecta")))
                .isInstanceOf(CredencialesInvalidasException.class).hasMessage("Credenciales inválidas.");
        verify(encoder).matches("incorrecta", "hash-real");
        verifyNoInteractions(tokens);
    }

    /** Incluso una coincidencia hipotética con el hash ficticio nunca autentica una cuenta inexistente. */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void cuentaInexistenteTambienVerificaHash(boolean matches) {
        when(encoder.matches("password-test-123", "hash-ficticio")).thenReturn(matches);
        assertThatThrownBy(() -> auth.autenticar(new LoginRequest("nadie@example.com", "password-test-123")))
                .isInstanceOf(CredencialesInvalidasException.class).hasMessage("Credenciales inválidas.");
        verify(encoder).matches("password-test-123", "hash-ficticio");
        verifyNoInteractions(tokens);
    }

    /** La respuesta de identidad corresponde al UUID proveniente de autenticación. */
    @Test
    void consultaUsuarioAutenticado() {
        UUID id = UUID.randomUUID();
        var usuario = new Usuario("ana@example.com", "hash-no-publicable", Rol.CLIENTE);
        ReflectionTestUtils.setField(usuario, "id", id);
        when(repository.findById(id)).thenReturn(Optional.of(usuario));
        assertThat(auth.obtenerAutenticado(id).id()).isEqualTo(id);
        assertThat(auth.obtenerAutenticado(id).roles()).containsExactly(Rol.CLIENTE);
    }

    /** Un token de una cuenta retirada no devuelve una identidad inventada. */
    @Test
    void cuentaRetiradaRechazaMe() {
        assertThatThrownBy(() -> auth.obtenerAutenticado(UUID.randomUUID()))
                .isInstanceOf(CredencialesInvalidasException.class);
    }

    /** Los DTOs de acceso no exponen secretos en su representación de diagnóstico. */
    @Test
    void ocultaCredencialesYTokenEnToString() {
        assertThat(new LoginRequest("ana@example.com", "password-no-publicable").toString())
                .doesNotContain("password-no-publicable");
        assertThat(new TokenResponse("token-no-publicable", "Bearer", 900).toString())
                .doesNotContain("token-no-publicable");
    }
}
