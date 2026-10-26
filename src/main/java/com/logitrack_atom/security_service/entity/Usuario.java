package com.logitrack_atom.security_service.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.logitrack_atom.security_service.enums.Rol;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Representa una cuenta de identidad persistida en security-service.
 *
 * <p>Almacena un hash adaptativo, nunca la contraseña original. Su UUID
 * identifica al usuario; no sustituye al identificador de cliente o repartidor.</p>
 *
 * @author MaxDz
 * @version 0.1.0
 * @see Rol
 */
@Entity
@Table(name = "usuarios")
public class Usuario extends BaseEntity {
    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    @JsonIgnore
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 16)
    private Rol rol;

    /** Constructor requerido por JPA. */
    protected Usuario() { }

    /**
     * Construye una cuenta con datos ya validados por su servicio.
     * @param email correo normalizado
     * @param passwordHash hash obtenido mediante PasswordEncoder
     * @param rol rol definido por una operación de confianza
     */
    public Usuario(String email, String passwordHash, Rol rol) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.rol = rol;
    }

    /**
     * Obtiene el correo normalizado de la cuenta.
     * @return correo canónico de la cuenta
     */
    public String getEmail() { return email; }

    /**
     * Obtiene el hash para verificar credenciales dentro del servicio.
     * @return hash utilizado internamente para verificar credenciales
     */
    public String getPasswordHash() { return passwordHash; }

    /**
     * Obtiene el rol de negocio de la cuenta.
     * @return rol asignado por el servicio
     */
    public Rol getRol() { return rol; }
}
