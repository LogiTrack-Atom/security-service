package com.logitrack_atom.security_service.service.impl;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.exception.EmailDuplicadoException;
import com.logitrack_atom.security_service.mapper.UsuarioMapper;
import com.logitrack_atom.security_service.repository.UsuarioRepository;
import com.logitrack_atom.security_service.service.UsuarioService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Implementa altas transaccionales sin permitir que la entrada pública elija roles.
 *
 * <p>La restricción única de MySQL complementa la consulta previa y protege
 * también los registros concurrentes con el mismo correo.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 * @see UsuarioService
 * @see UsuarioRepository
 */
@Service
public class UsuarioServiceImpl implements UsuarioService {
    private final UsuarioRepository usuarios;
    private final PasswordEncoder encoder;
    private final UsuarioMapper mapper;

    /**
     * Recibe las dependencias mediante constructor.
     * @param usuarios repositorio de cuentas
     * @param encoder codificador adaptativo de contraseña
     * @param mapper conversor a respuestas seguras
     */
    public UsuarioServiceImpl(UsuarioRepository usuarios, PasswordEncoder encoder, UsuarioMapper mapper) {
        this.usuarios = usuarios;
        this.encoder = encoder;
        this.mapper = mapper;
    }

    /** {@inheritDoc} */
    @Override
    @Transactional
    public UsuarioResponse registrar(RegistroRequest request) {
        if (usuarios.existsByEmail(request.email())) throw new EmailDuplicadoException();
        Usuario usuario = new Usuario(request.email(), encoder.encode(request.password()), Rol.CLIENTE);
        return mapper.toResponse(usuarios.saveAndFlush(usuario));
    }

    /** {@inheritDoc} */
    @Override
    @Transactional
    public void asegurarAdministradorInicial(RegistroRequest request) {
        var existente = usuarios.findByEmail(request.email());
        if (existente.isPresent()) {
            if (existente.get().getRol() != Rol.ADMIN) {
                throw new IllegalStateException("El correo del administrador inicial pertenece a otra cuenta.");
            }
            return;
        }
        usuarios.saveAndFlush(new Usuario(request.email(), encoder.encode(request.password()), Rol.ADMIN));
    }
}
