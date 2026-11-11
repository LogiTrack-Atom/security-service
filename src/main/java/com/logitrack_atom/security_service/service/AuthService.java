package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.exception.CredencialesInvalidasException;
import java.util.UUID;

/**
 * Define autenticación por credenciales y consulta de la identidad autenticada.
 *
 * <p>El login no recibe roles ni identificadores de dominio. La consulta de
 * identidad utiliza únicamente el sub que validó la cadena de seguridad.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 * @see LoginRequest
 * @see TokenResponse
 */
public interface AuthService {
    /** Verifica credenciales para crear una sesión interna sin recibir roles del cliente.
     * @param request credenciales validadas
     * @return cuenta persistida; no se serializa desde controladores
     */
    com.logitrack_atom.security_service.entity.Usuario autenticarCuenta(LoginRequest request);

    /**
     * Autentica credenciales y emite un token de acceso.
     * @param request credenciales validadas en la frontera HTTP
     * @return token firmado con los roles persistidos
     * @throws CredencialesInvalidasException si no existe la cuenta o no coincide la contraseña
     */
    TokenResponse autenticar(LoginRequest request);

    /**
     * Consulta la cuenta correspondiente a una identidad ya autenticada.
     * @param usuarioId sub UUID obtenido del JWT validado
     * @return respuesta pública del usuario
     * @throws CredencialesInvalidasException si la cuenta ya no existe
     */
    UsuarioResponse obtenerAutenticado(UUID usuarioId);
}
