package com.logitrack_atom.security_service.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

/** Familia de renovación: identidad, vencimiento absoluto y hash del token vigente. */
@Entity
@Table(name = "refresh_sessions")
public class RefreshSession {
    @Id private UUID id;
    @Column(name = "usuario_id", nullable = false) private UUID usuarioId;
    @Column(name = "token_hash", nullable = false, length = 64) private String tokenHash;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(nullable = false) private boolean revoked;

    /** Constructor de persistencia. */
    protected RefreshSession() { }
    /** Crea una familia sin persistir la credencial opaca.
     * @param id selector aleatorio de la familia
     * @param usuarioId identidad autenticada
     * @param tokenHash hash SHA-256 del token
     * @param expiresAt vencimiento absoluto, sin prórroga por rotación
     */
    public RefreshSession(UUID id, UUID usuarioId, String tokenHash, Instant expiresAt) {
        this.id = id; this.usuarioId = usuarioId; this.tokenHash = tokenHash; this.expiresAt = expiresAt;
    }
    /** Consulta el valor o respuesta del contrato.
     * @return selector de familia, no una credencial */
    public UUID getId() { return id; }
    /** Consulta el valor o respuesta del contrato.
     * @return identidad persistida */
    public UUID getUsuarioId() { return usuarioId; }
    /** Consulta el valor o respuesta del contrato.
     * @return hash interno, nunca incluido en DTO HTTP */
    public String getTokenHash() { return tokenHash; }
    /** Consulta el valor o respuesta del contrato.
     * @return límite absoluto de renovación */
    public Instant getExpiresAt() { return expiresAt; }
    /** Consulta el valor o respuesta del contrato.
     * @return true si la familia ya no puede renovar */
    public boolean isRevoked() { return revoked; }
    /** Sustituye el hash durante una rotación con bloqueo de fila.
     * @param hash siguiente hash de renovación
     */
    public void rotate(String hash) { tokenHash = hash; }
    /** Invalida todas las renovaciones de la familia. */
    public void revoke() { revoked = true; }
}
