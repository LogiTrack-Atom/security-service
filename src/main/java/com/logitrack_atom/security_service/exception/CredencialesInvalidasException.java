package com.logitrack_atom.security_service.exception;

/**
 * Rechaza accesos sin revelar si la cuenta existe o qué credencial fue incorrecta.
 *
 * @author MaxDz
 * @version 0.2.0
 */
public class CredencialesInvalidasException extends RuntimeException {
    /** Construye una denegación genérica sin datos del solicitante. */
    public CredencialesInvalidasException() { super("Credenciales inválidas."); }
}
