package com.logitrack_atom.security_service.controller;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.net.URI;

/**
 * Recibe el registro de cuentas públicas y delega las reglas al servicio.
 *
 * @author MaxDz
 * @version 0.1.0
 * @see UsuarioService
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UsuarioService usuarios;

    /**
     * Construye el controlador con su contrato de negocio.
     * @param usuarios servicio de registro
     */
    public AuthController(UsuarioService usuarios) { this.usuarios = usuarios; }

    /**
     * Registra una cuenta CLIENTE sin aceptar roles ni asociaciones externas.
     * @param request credenciales validadas
     * @return respuesta 201 con datos seguros de la nueva cuenta
     */
    @PostMapping("/register")
    public ResponseEntity<UsuarioResponse> registrar(@Valid @RequestBody RegistroRequest request) {
        UsuarioResponse response = usuarios.registrar(request);
        return ResponseEntity.created(URI.create("/api/v1/usuarios/" + response.id())).body(response);
    }
}
