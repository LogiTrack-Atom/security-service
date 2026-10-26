package com.logitrack_atom.security_service.service.impl;

import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.exception.CredencialesInvalidasException;
import com.logitrack_atom.security_service.mapper.UsuarioMapper;
import com.logitrack_atom.security_service.repository.UsuarioRepository;
import com.logitrack_atom.security_service.service.AuthService;
import com.logitrack_atom.security_service.service.JwtTokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;

/**
 * Autentica contra hashes persistidos y conserva un rechazo uniforme de credenciales.
 *
 * <p>Para una cuenta inexistente también se verifica un hash BCrypt ficticio,
 * evitando omitir el trabajo criptográfico y revelar su existencia por ese atajo.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
@Service
public class AuthServiceImpl implements AuthService {
    private final UsuarioRepository usuarios;
    private final PasswordEncoder encoder;
    private final JwtTokenService tokens;
    private final UsuarioMapper mapper;
    private final String hashFicticio;

    /**
     * Prepara la autenticación sin credenciales por defecto ni hashes compartidos en Git.
     * @param usuarios repositorio de cuentas
     * @param encoder verificador de contraseñas
     * @param tokens emisor de JWT
     * @param mapper conversor de respuestas seguras
     */
    public AuthServiceImpl(UsuarioRepository usuarios, PasswordEncoder encoder,
                           JwtTokenService tokens, UsuarioMapper mapper) {
        this.usuarios = usuarios;
        this.encoder = encoder;
        this.tokens = tokens;
        this.mapper = mapper;
        this.hashFicticio = encoder.encode(UUID.randomUUID().toString());
    }

    /** {@inheritDoc} */
    @Override
    @Transactional(readOnly = true)
    public TokenResponse autenticar(LoginRequest request) {
        var usuario = usuarios.findByEmail(request.email());
        String hash = usuario.map(value -> value.getPasswordHash()).orElse(hashFicticio);
        boolean coincide = encoder.matches(request.password(), hash);
        if (usuario.isEmpty() || !coincide) throw new CredencialesInvalidasException();
        return tokens.emitir(usuario.get());
    }

    /** {@inheritDoc} */
    @Override
    @Transactional(readOnly = true)
    public UsuarioResponse obtenerAutenticado(UUID usuarioId) {
        return usuarios.findById(usuarioId).map(mapper::toResponse)
                .orElseThrow(CredencialesInvalidasException::new);
    }
}
