package com.logitrack_atom.security_service.service.impl;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.request.UsuarioCreateRequest;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.exception.EmailDuplicadoException;
import com.logitrack_atom.security_service.exception.RecursoNoEncontradoException;
import com.logitrack_atom.security_service.mapper.UsuarioMapper;
import com.logitrack_atom.security_service.repository.UsuarioRepository;
import com.logitrack_atom.security_service.service.UsuarioService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;

/**
 * Implementa registro y administración transaccional sin exponer credenciales.
 *
 * <p>La restricción única de MySQL complementa la consulta previa y protege
 * también los registros concurrentes con el mismo correo.</p>
 *
 * @author MaxDz
 * @version 0.2.0
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
        return crearCuenta(request.email(), request.password(), Rol.CLIENTE);
    }

    /** {@inheritDoc} */
    @Override
    @Transactional
    public UsuarioResponse crearAdministrativo(UsuarioCreateRequest request) {
        return crearCuenta(request.email(), request.password(), request.rol());
    }

    /** {@inheritDoc} */
    @Override
    @Transactional(readOnly = true)
    public UsuarioResponse obtener(UUID id) {
        return usuarios.findById(id).map(mapper::toResponse).orElseThrow(RecursoNoEncontradoException::new);
    }

    /**
     * Comparte unicidad y codificación sin mezclar las políticas de elección de rol.
     * @param email correo canónico validado
     * @param password contraseña original validada
     * @param rol rol impuesto por registro o elegido por la operación administrativa
     * @return cuenta persistida sin credenciales
     * @throws EmailDuplicadoException si el correo ya está registrado
     */
    private UsuarioResponse crearCuenta(String email, String password, Rol rol) {
        if (usuarios.existsByEmail(email)) throw new EmailDuplicadoException();
        return mapper.toResponse(usuarios.saveAndFlush(new Usuario(email, encoder.encode(password), rol)));
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
