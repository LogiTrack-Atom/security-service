package com.logitrack_atom.security_service.repository;

import com.logitrack_atom.security_service.entity.RefreshSession;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.util.Optional;
import java.util.UUID;

/** Serializa rotación y revocación por familia en la base propia. */
public interface RefreshSessionRepository extends JpaRepository<RefreshSession, UUID> {
    /** Bloquea la familia hasta finalizar la transacción.
     * @param id selector del token opaco
     * @return familia o vacío; no autentica el secreto por sí solo
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from RefreshSession s where s.id = :id")
    Optional<RefreshSession> lockById(@Param("id") UUID id);
}
