package com.logitrack_atom.security_service.exception;

/**
 * Indica que una consulta administrativa no encontró la cuenta solicitada.
 *
 * @author MaxDz
 * @version 0.2.0
 */
public class RecursoNoEncontradoException extends RuntimeException {
    /** Construye un error sin incorporar identificadores ni credenciales. */
    public RecursoNoEncontradoException() { super("No se encontró el usuario solicitado."); }
}
