package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.request.UsuarioCreateRequest;
import com.logitrack_atom.security_service.entity.Usuario;
import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.exception.EmailDuplicadoException;
import com.logitrack_atom.security_service.exception.RecursoNoEncontradoException;
import com.logitrack_atom.security_service.mapper.UsuarioMapper;
import com.logitrack_atom.security_service.repository.UsuarioRepository;
import com.logitrack_atom.security_service.service.impl.UsuarioServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.Optional;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Verifica registro, administración y bootstrap sin Spring, Docker ni base de datos.
 *
 * @author MaxDz
 * @version 0.2.0
 */
@ExtendWith(MockitoExtension.class)
class UsuarioServiceTest {
    @Mock private UsuarioRepository repository;
    @Mock private PasswordEncoder encoder;
    private UsuarioService service;

    /** Prepara el servicio real con colaboradores controlados. */
    @BeforeEach
    void preparar() { service = new UsuarioServiceImpl(repository, encoder, new UsuarioMapper()); }

    /** Comprueba que el rol y el hash persistidos provienen del servicio. */
    @Test
    void registroAsignaClienteYConservaLaContrasenaSinNormalizar() {
        var request = new RegistroRequest("  Ana@EXAMPLE.COM  ", "  contraseña-ejemplo  ");
        when(encoder.encode(request.password())).thenReturn("hash-de-prueba");
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.registrar(request);

        var captor = ArgumentCaptor.forClass(Usuario.class);
        verify(repository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("ana@example.com");
        assertThat(captor.getValue().getRol()).isEqualTo(Rol.CLIENTE);
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("hash-de-prueba");
        assertThat(response.roles()).containsExactly(Rol.CLIENTE);
        verify(encoder).encode("  contraseña-ejemplo  ");
    }

    /** Un duplicado se rechaza antes de calcular el hash o escribir datos. */
    @Test
    void correoExistenteNoSeModifica() {
        when(repository.existsByEmail("ana@example.com")).thenReturn(true);
        assertThatThrownBy(() -> service.registrar(new RegistroRequest("ANA@example.com", "password-test-123")))
                .isInstanceOf(EmailDuplicadoException.class);
        verify(repository, never()).saveAndFlush(any());
        verifyNoInteractions(encoder);
    }

    /** El alta administrativa utiliza exclusivamente el rol elegido y un hash del encoder. */
    @ParameterizedTest
    @EnumSource(Rol.class)
    void altaAdministrativaPersisteRolYHash(Rol rol) {
        var request = new UsuarioCreateRequest("  Operador@EXAMPLE.COM ", "  contraseña-ejemplo  ", rol);
        when(encoder.encode(request.password())).thenReturn("hash-administrativo");
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.crearAdministrativo(request);

        var captor = ArgumentCaptor.forClass(Usuario.class);
        verify(repository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("operador@example.com");
        assertThat(captor.getValue().getRol()).isEqualTo(rol);
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("hash-administrativo");
        assertThat(response.roles()).containsExactly(rol);
        verify(encoder).encode(request.password());
    }

    /** Crear con un correo ocupado no restablece contraseñas ni promueve la cuenta. */
    @Test
    void altaAdministrativaRechazaDuplicadosSinEscribir() {
        when(repository.existsByEmail("ana@example.com")).thenReturn(true);
        assertThatThrownBy(() -> service.crearAdministrativo(
                new UsuarioCreateRequest("ANA@example.com", "password-test-123", Rol.ADMIN)))
                .isInstanceOf(EmailDuplicadoException.class);
        verify(repository, never()).saveAndFlush(any());
        verifyNoInteractions(encoder);
    }

    /** La consulta usa el UUID indicado y transforma la entidad a su respuesta segura. */
    @Test
    void consultaAdministrativaDevuelveIdentidadSinCodificar() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.of(
                new Usuario("repartidor@example.com", "hash-interno", Rol.REPARTIDOR)));
        var response = service.obtener(id);
        assertThat(response.email()).isEqualTo("repartidor@example.com");
        assertThat(response.roles()).containsExactly(Rol.REPARTIDOR);
        assertThat(response.toString()).doesNotContain("hash-interno");
        verify(repository).findById(id);
        verify(repository, never()).saveAndFlush(any());
        verifyNoInteractions(encoder);
    }

    /** La ausencia administrativa se diferencia del rechazo de credenciales del login. */
    @Test
    void consultaInexistenteProduceErrorDeRecurso() {
        UUID id = UUID.randomUUID();
        assertThatThrownBy(() -> service.obtener(id)).isInstanceOf(RecursoNoEncontradoException.class);
        verify(repository).findById(id);
        verifyNoInteractions(encoder);
    }

    /** El procedimiento interno crea ADMIN cuando la cuenta todavía no existe. */
    @Test
    void bootstrapCreaAdminConHash() {
        var request = new RegistroRequest("admin@example.com", "password-test-123");
        when(encoder.encode(request.password())).thenReturn("hash-de-prueba");
        service.asegurarAdministradorInicial(request);
        var captor = ArgumentCaptor.forClass(Usuario.class);
        verify(repository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getRol()).isEqualTo(Rol.ADMIN);
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("hash-de-prueba");
    }

    /** Repetir el bootstrap no reemplaza la contraseña existente. */
    @Test
    void bootstrapEsIdempotente() {
        when(repository.findByEmail("admin@example.com"))
                .thenReturn(Optional.of(new Usuario("admin@example.com", "hash-original", Rol.ADMIN)));
        service.asegurarAdministradorInicial(new RegistroRequest("admin@example.com", "otra-password-123"));
        verify(repository, never()).saveAndFlush(any());
        verifyNoInteractions(encoder);
    }

    /** El bootstrap nunca promueve una cuenta creada por el registro público. */
    @Test
    void bootstrapRechazaCorreoDeUnCliente() {
        when(repository.findByEmail("ana@example.com"))
                .thenReturn(Optional.of(new Usuario("ana@example.com", "hash-original", Rol.CLIENTE)));
        assertThatThrownBy(() -> service.asegurarAdministradorInicial(
                new RegistroRequest("ana@example.com", "password-test-123")))
                .isInstanceOf(IllegalStateException.class);
        verify(repository, never()).saveAndFlush(any());
        verifyNoInteractions(encoder);
    }
}
