package com.logitrack_atom.security_service.dto.request;

import com.logitrack_atom.security_service.validation.MaxUtf8Bytes;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Locale;

/**
 * Recibe las únicas credenciales admitidas por el registro público.
 *
 * <p>El rol y los identificadores de dominio no forman parte de la solicitud.
 * La contraseña conserva exactamente los caracteres enviados.</p>
 *
 * @param email correo único, normalizado al construir el DTO
 * @param password contraseña de al menos 12 caracteres y hasta 72 bytes UTF-8
 * @author MaxDz
 * @version 0.1.0
 */
public record RegistroRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(min = 12, max = 72) @MaxUtf8Bytes(72) String password) {

    /**
     * Normaliza el correo con una regla independiente del locale del servidor.
     * @param email correo recibido
     * @param password contraseña sin normalización
     */
    public RegistroRequest {
        email = email == null ? null : email.strip().toLowerCase(Locale.ROOT);
    }

    /**
     * Evita exponer contraseñas al inspeccionar el DTO.
     * @return descripción sin credenciales
     */
    @Override
    public String toString() { return "RegistroRequest[credenciales protegidas]"; }
}
