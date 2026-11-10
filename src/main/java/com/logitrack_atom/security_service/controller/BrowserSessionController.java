package com.logitrack_atom.security_service.controller;

import com.logitrack_atom.security_service.config.SessionProperties;
import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.exception.CredencialesInvalidasException;
import com.logitrack_atom.security_service.service.BrowserSessionService;
import jakarta.servlet.http.*;
import jakarta.validation.Valid;
import java.time.*;
import java.util.Arrays;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

/** Sesión del navegador de origen único; nunca devuelve el refresh en JSON. */
@RestController
@RequestMapping("/api/v1/auth/session")
public class BrowserSessionController {
    /** Nombre host-only y ruta raíz exigidos por el prefijo seguro. */
    public static final String COOKIE = "__Host-logitrack_refresh";
    private final BrowserSessionService sessions;
    private final SessionProperties policy;
    private final Clock clock;

    /** Inyecta renovación y política del origen confiable.
     * @param sessions servicio transaccional de renovación
     * @param policy origen externo exacto
     * @param clock reloj para la edad restante de la cookie
     */
    public BrowserSessionController(BrowserSessionService sessions, SessionProperties policy, Clock clock) {
        this.sessions = sessions; this.policy = policy; this.clock = clock;
    }

    /** Autentica el navegador sin cambiar el login Bearer tradicional.
     * @param body credenciales validadas
     * @param request solicitud usada para comprobar origen y cabecera CSRF
     * @return acceso en JSON y renovación exclusivamente en Set-Cookie
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        if (!trusted(request)) return denied();
        var grant = sessions.login(body, cookie(request));
        return grant(grant);
    }

    /** Rota la cookie válida; un rechazo elimina la copia del navegador.
     * @param request solicitud del mismo origen
     * @return nuevo acceso o 401 sin cuerpos de credenciales
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        if (!trusted(request)) return denied();
        try { return grant(sessions.refresh(cookie(request))); }
        catch (CredencialesInvalidasException invalid) {
            return ResponseEntity.status(401).cacheControl(CacheControl.noStore())
                    .header(HttpHeaders.SET_COOKIE, expired()).build();
        }
    }

    /** Revoca la renovación y elimina cookie; no revoca un Bearer copiado.
     * @param request solicitud protegida frente a CSRF
     * @return 204 idempotente sin contenido
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        if (!trusted(request)) return denied();
        sessions.logout(cookie(request));
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, expired()).build();
    }

    /** Exige cabecera no simple y Origin exacto; no confía en Host/Forwarded del cliente.
     * @param request solicitud del navegador
     * @return true únicamente para el origen configurado y cabecera explícita
     */
    private boolean trusted(HttpServletRequest request) {
        return policy.origin().equals(request.getHeader(HttpHeaders.ORIGIN))
                && "1".equals(request.getHeader("X-LogiTrack-Session"))
                && !"cross-site".equals(request.getHeader("Sec-Fetch-Site"));
    }
    /** Rechaza cookies duplicadas o ambiguas en lugar de elegir una por orden.
     * @param request solicitud recibida
     * @return credencial única o null
     */
    private String cookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        var values = Arrays.stream(request.getCookies()).filter(c -> COOKIE.equals(c.getName())).toList();
        return values.size() == 1 ? values.getFirst().getValue() : null;
    }
    /** Construye respuesta no cacheable sin serializar la credencial de renovación.
     * @param grant resultado interno seguro por contrato
     * @return token de acceso y cookie protegida
     */
    private ResponseEntity<?> grant(BrowserSessionService.Grant grant) {
        long seconds = Math.max(0, Duration.between(clock.instant(), grant.expiresAt()).toSeconds());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache")
                .header(HttpHeaders.SET_COOKIE, protectedCookie(grant.refresh()).maxAge(seconds).build().toString())
                .body(grant.access());
    }
    /** Consulta el valor o respuesta del contrato.
     * @return denegación sin alterar una cookie que puede pertenecer a otro origen */
    private ResponseEntity<Void> denied() { return ResponseEntity.status(403).cacheControl(CacheControl.noStore()).build(); }
    /** Consulta el valor o respuesta del contrato.
     * @return cookie expirada con los mismos atributos de emisión */
    private String expired() { return protectedCookie("").maxAge(0).build().toString(); }
    /** Aplica HttpOnly, Secure, SameSite y alcance host-only de forma invariable.
     * @param value valor opaco interno
     * @return constructor sin Domain ni acceso JavaScript
     */
    private ResponseCookie.ResponseCookieBuilder protectedCookie(String value) {
        return ResponseCookie.from(COOKIE, value).httpOnly(true).secure(true).sameSite("Strict").path("/");
    }
}
