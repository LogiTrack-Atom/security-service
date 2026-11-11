package com.logitrack_atom.security_service.dto.response;

import com.logitrack_atom.security_service.enums.Rol;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Expone los datos de una cuenta sin incluir contraseña ni hash.
 *
 * @param id UUID de usuario, independiente del dominio de envíos
 * @param email correo canónico
 * @param roles roles asignados por el servicio
 * @param createdAt instante de creación UTC
 * @param updatedAt instante de actualización UTC
 * @author MaxDz
 * @version 0.1.0
 */
public record UsuarioResponse(UUID id, String email, Set<Rol> roles,
                              Instant createdAt, Instant updatedAt) { }
