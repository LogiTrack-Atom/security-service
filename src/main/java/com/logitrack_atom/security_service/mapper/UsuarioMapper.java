package com.logitrack_atom.security_service.mapper;

import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.entity.Usuario;
import org.springframework.stereotype.Component;
import java.util.Set;

/**
 * Convierte las cuentas persistidas a respuestas que excluyen credenciales.
 *
 * @author MaxDz
 * @version 0.1.0
 */
@Component
public class UsuarioMapper {
    /** Crea el conversor de cuentas a respuestas públicas. */
    public UsuarioMapper() { }

    /**
     * Mapea exclusivamente los atributos públicos del usuario.
     * @param usuario cuenta persistida
     * @return DTO de identidad sin contraseña ni hash
     */
    public UsuarioResponse toResponse(Usuario usuario) {
        return new UsuarioResponse(usuario.getId(), usuario.getEmail(), Set.of(usuario.getRol()),
                usuario.getCreatedAt(), usuario.getUpdatedAt());
    }
}
