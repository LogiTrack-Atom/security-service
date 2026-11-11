package com.logitrack_atom.security_service.repository;

import com.logitrack_atom.security_service.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

/**
 * Accede exclusivamente a las cuentas de la base propia de security-service.
 *
 * @author MaxDz
 * @version 0.1.0
 * @see Usuario
 */
public interface UsuarioRepository extends JpaRepository<Usuario, UUID> {
    /**
     * Busca una cuenta por su correo canónico.
     * @param email correo previamente normalizado
     * @return cuenta encontrada o vacío
     */
    Optional<Usuario> findByEmail(String email);

    /**
     * Comprueba la unicidad antes de intentar el alta.
     * @param email correo previamente normalizado
     * @return true si ya existe una cuenta
     */
    boolean existsByEmail(String email);
}
