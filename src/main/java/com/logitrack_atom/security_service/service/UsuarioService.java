package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.request.UsuarioCreateRequest;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.exception.EmailDuplicadoException;
import com.logitrack_atom.security_service.exception.RecursoNoEncontradoException;
import java.util.UUID;

/**
 * Define el registro y la administración de identidades de LogiTrack.
 *
 * <p>La API trabaja con DTOs. El alta pública no recibe roles y el
 * aprovisionamiento inicial de ADMIN no se expone mediante un controller.</p>
 *
 * @author MaxDz
 * @version 0.2.0
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
     * Crea una cuenta con un rol explícito desde la API exclusiva de ADMIN.
     *
     * <p>Un correo existente no se modifica ni se promueve. La contraseña
     * se codifica antes de persistir y no se incorpora a la respuesta.</p>
     *
     * @param request credenciales y rol previamente validados
     * @return datos seguros de la cuenta creada
     * @throws EmailDuplicadoException si el correo ya está registrado
     */
    UsuarioResponse crearAdministrativo(UsuarioCreateRequest request);

    /**
     * Consulta una cuenta para verificar su UUID y rol desde una operación ADMIN.
     * @param id UUID de usuario independiente de la identidad de dominio
     * @return datos seguros de la cuenta persistida
     * @throws RecursoNoEncontradoException si no existe la cuenta
     */
    UsuarioResponse obtener(UUID id);

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
