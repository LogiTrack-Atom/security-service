package com.logitrack_atom.security_service.exception;

/**
 * Indica que el correo canónico ya pertenece a otra cuenta.
 *
 * @author MaxDz
 * @version 0.1.0
 */
public class EmailDuplicadoException extends RuntimeException {
    /** Construye un conflicto sin incorporar credenciales a su mensaje. */
    public EmailDuplicadoException() { super("Ya existe una cuenta con ese correo."); }
}
