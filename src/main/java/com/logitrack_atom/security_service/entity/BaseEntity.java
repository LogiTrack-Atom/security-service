package com.logitrack_atom.security_service.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Define identidad UUID y auditoría UTC de las entidades del servicio.
 *
 * <p>Las fechas son administradas por JPA y no se reciben desde la API.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {
    /** Inicializa los campos que serán administrados por JPA. */
    protected BaseEntity() { }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Obtiene el UUID del recurso.
     * @return identificador persistente del recurso
     */
    public UUID getId() { return id; }

    /**
     * Obtiene la fecha de creación.
     * @return instante de creación en UTC
     */
    public Instant getCreatedAt() { return createdAt; }

    /**
     * Obtiene la fecha de la última modificación.
     * @return instante de la última modificación en UTC
     */
    public Instant getUpdatedAt() { return updatedAt; }
}
