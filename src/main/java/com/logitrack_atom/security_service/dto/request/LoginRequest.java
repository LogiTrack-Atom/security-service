package com.logitrack_atom.security_service.dto.request;

import com.logitrack_atom.security_service.validation.MaxUtf8Bytes;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Locale;

/**
 * Recibe credenciales sin permitir seleccionar la identidad ni los roles del token.
 *
 * @param email correo normalizado con la misma regla del registro
 * @param password contraseña original; un valor incorrecto produce 401
 * @author MaxDz
 * @version 0.2.0
 */
public record LoginRequest(@NotBlank @Email @Size(max = 254) String email,
                           @NotBlank @Size(max = 72) @MaxUtf8Bytes(72) String password) {
    /**
     * Normaliza solo el identificador de acceso.
     * @param email correo recibido
     * @param password contraseña sin alteración
     */
    public LoginRequest {
        email = email == null ? null : email.strip().toLowerCase(Locale.ROOT);
    }

    /**
     * Evita imprimir la contraseña al inspeccionar la solicitud.
     * @return representación sin credenciales
     */
    @Override
    public String toString() { return "LoginRequest[credenciales protegidas]"; }
}
