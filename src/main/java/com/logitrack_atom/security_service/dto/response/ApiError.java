package com.logitrack_atom.security_service.dto.response;

import java.time.Instant;
import java.util.List;

/**
 * Mantiene el formato de error compartido con shipment-service.
 *
 * @param timestamp instante UTC del error
 * @param status código HTTP
 * @param error descripción HTTP
 * @param mensaje explicación segura de la operación rechazada
 * @param detalles errores de validación sin valores sensibles
 * @author MaxDz
 * @version 0.1.0
 */
public record ApiError(Instant timestamp, int status, String error,
                       String mensaje, List<String> detalles) { }
