package com.logitrack_atom.security_service.controller;

import com.logitrack_atom.security_service.dto.request.RegistroRequest;
import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.service.UsuarioService;
import com.logitrack_atom.security_service.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.net.URI;
import java.util.UUID;

/**
 * Expone registro, login e identidad autenticada sin exponer entidades persistidas.
 *
 * @author MaxDz
 * @version 0.2.0
 * @see UsuarioService
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UsuarioService usuarios;
    private final AuthService auth;

    /**
     * Construye el controlador con su contrato de negocio.
     * @param usuarios servicio de registro
     * @param auth servicio de autenticación
     */
    public AuthController(UsuarioService usuarios, AuthService auth) {
        this.usuarios = usuarios;
        this.auth = auth;
    }

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

    /**
     * Entrega un token únicamente después de validar las credenciales persistidas.
     * @param request credenciales de acceso
     * @return token Bearer sin almacenamiento en caché
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache")
                .body(auth.autenticar(request));
    }

    /**
     * Consulta el usuario indicado por el sub del token validado.
     * @param jwt principal autenticado por Spring Security
     * @return identidad pública, sin aceptar un usuario objetivo desde el cliente
     */
    @GetMapping("/me")
    public ResponseEntity<UsuarioResponse> me(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache")
                .body(auth.obtenerAutenticado(UUID.fromString(jwt.getSubject())));
    }
}
