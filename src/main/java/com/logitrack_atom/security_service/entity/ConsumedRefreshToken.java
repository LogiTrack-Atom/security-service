package com.logitrack_atom.security_service.entity;

import jakarta.persistence.*;
import java.util.UUID;

/** Hash consumido para distinguir reutilización real de un secreto aleatorio inválido. */
@Entity
@Table(name = "consumed_refresh_tokens")
public class ConsumedRefreshToken {
    @Id @Column(name = "token_hash", length = 64) private String tokenHash;
    @Column(name = "session_id", nullable = false) private UUID sessionId;
    /** Constructor de persistencia. */
    protected ConsumedRefreshToken() { }
    /** Registra únicamente el hash consumido y su familia.
     * @param tokenHash hash del token anterior
     * @param sessionId selector de la familia
     */
    public ConsumedRefreshToken(String tokenHash, UUID sessionId) { this.tokenHash = tokenHash; this.sessionId = sessionId; }
    /** Consulta el valor o respuesta del contrato.
     * @return familia a la que pertenecía el hash */
    public UUID getSessionId() { return sessionId; }
}
