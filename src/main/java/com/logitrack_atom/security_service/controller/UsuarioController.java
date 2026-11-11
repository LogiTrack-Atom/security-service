package com.logitrack_atom.security_service.controller;

import com.logitrack_atom.security_service.dto.request.UsuarioCreateRequest;
import com.logitrack_atom.security_service.dto.response.UsuarioResponse;
import com.logitrack_atom.security_service.exception.EmailDuplicadoException;
import com.logitrack_atom.security_service.exception.RecursoNoEncontradoException;
import com.logitrack_atom.security_service.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.net.URI;
import java.util.UUID;

/**
 * Expone altas y consultas administrativas de identidad mediante DTOs seguros.
 *
 * <p>La cadena de seguridad exige un JWT válido con rol ADMIN para ambas
 * operaciones. Las asociaciones con clientes y repartidores se administran
 * en sus servicios propietarios, utilizando el UUID y el rol consultados aquí.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 * @see UsuarioService
 * @see UsuarioCreateRequest
 * @see UsuarioResponse
 */
@RestController
@RequestMapping("/api/v1/usuarios")
public class UsuarioController {
    private final UsuarioService usuarios;

    /**
     * Recibe el contrato de negocio mediante inyección por constructor.
     * @param usuarios servicio de gestión de cuentas
     */
    public UsuarioController(UsuarioService usuarios) { this.usuarios = usuarios; }

    /**
     * Crea una cuenta con el rol seleccionado por el administrador autenticado.
     * @param request credenciales y rol validados
     * @return respuesta 201 sin contraseña ni hash y con ubicación del recurso
     * @throws EmailDuplicadoException si el correo ya pertenece a una cuenta
     */
    @PostMapping
    public ResponseEntity<UsuarioResponse> crear(@Valid @RequestBody UsuarioCreateRequest request) {
        UsuarioResponse response = usuarios.crearAdministrativo(request);
        return ResponseEntity.created(URI.create("/api/v1/usuarios/" + response.id()))
                .cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache").body(response);
    }

    /**
     * Obtiene la identidad necesaria para una vinculación administrativa.
     * @param id UUID de la cuenta a consultar
     * @return respuesta 200 con UUID, correo, roles y auditoría sin credenciales
     * @throws RecursoNoEncontradoException si la cuenta no existe
     */
    @GetMapping("/{id}")
    public ResponseEntity<UsuarioResponse> obtener(@PathVariable UUID id) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache")
                .body(usuarios.obtener(id));
    }
}
