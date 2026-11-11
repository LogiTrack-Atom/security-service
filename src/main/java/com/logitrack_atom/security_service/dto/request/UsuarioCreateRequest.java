package com.logitrack_atom.security_service.dto.request;

import com.logitrack_atom.security_service.enums.Rol;
import com.logitrack_atom.security_service.validation.MaxUtf8Bytes;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Locale;

/**
 * Define el alta administrativa de una cuenta con un único rol explícito.
 *
 * <p>Solo la API autorizada para ADMIN utiliza este DTO. No recibe UUID,
 * auditoría ni asociaciones con clientes o repartidores. La contraseña
 * conserva sus caracteres y se protege en la representación de diagnóstico.</p>
 *
 * @param email correo único normalizado al construir la solicitud
 * @param password contraseña de 12 a 72 caracteres y hasta 72 bytes UTF-8
 * @param rol rol de negocio elegido por el administrador
 * @author MaxDz
 * @version 0.2.0
 * @see Rol
 */
public record UsuarioCreateRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(min = 12, max = 72) @MaxUtf8Bytes(72) String password,
        @NotNull Rol rol) {

    /**
     * Aplica la misma normalización de correo utilizada en registro y login.
     * @param email correo recibido
     * @param password contraseña sin recortar ni normalizar
     * @param rol rol recibido, sujeto a validación
     */
    public UsuarioCreateRequest {
        email = email == null ? null : email.strip().toLowerCase(Locale.ROOT);
    }

    /**
     * Omite las credenciales al inspeccionar la solicitud.
     * @return descripción sin datos sensibles
     */
    @Override
    public String toString() { return "UsuarioCreateRequest[credenciales protegidas]"; }
}
