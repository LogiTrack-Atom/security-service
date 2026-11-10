package com.logitrack_atom.security_service.repository;

import com.logitrack_atom.security_service.entity.ConsumedRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

/** Conserva hashes históricos de la familia hasta su eliminación por mantenimiento. */
public interface ConsumedRefreshTokenRepository extends JpaRepository<ConsumedRefreshToken, String> { }
