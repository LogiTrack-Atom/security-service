package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.exception.EmailDuplicadoException;

/**
 * Define las operaciones iniciales de alta de identidad de LogiTrack.
 *
 * <p>La API trabaja con DTOs. El alta pública no recibe roles y el
 * aprovisionamiento inicial de ADMIN no se expone mediante un controller.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 * @see RegistroRequest
 * @see UsuarioResponse
 */
public interface UsuarioService {
    /**
     * Registra una cuenta CLIENTE con correo y contraseña ya validados.
     * @param request credenciales de registro
     * @return datos de la cuenta persistida sin hash
     * @throws EmailDuplicadoException si el correo ya está registrado
     */
    UsuarioResponse registrar(RegistroRequest request);

    /**
     * Crea ADMIN únicamente cuando no existe una cuenta con ese correo.
     *
     * <p>Si ya existe ADMIN no modifica su contraseña. Una cuenta con otro
     * rol nunca se promueve mediante este procedimiento.</p>
     *
     * @param request credenciales externas validadas del administrador inicial
     * @throws IllegalStateException si el correo está ocupado por otro rol
     */
    void asegurarAdministradorInicial(RegistroRequest request);
}
