package com.logitrack_atom.security_service.exception;

import com.logitrack_atom.security_service.dto.response.ApiError;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.ErrorResponse;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import java.time.Instant;
import java.util.List;

/**
 * Traduce errores de registro a respuestas HTTP sin revelar valores sensibles.
 *
 * @author MaxDz
 * @version 0.1.0
 * @see ApiError
 */
@RestControllerAdvice
public class GlobalExceptionHandler {
    /** Crea el traductor global de errores de registro. */
    public GlobalExceptionHandler() { }

    /**
     * Conserva los estados del protocolo para métodos o tipos de contenido no admitidos.
     * @param ex error HTTP producido por Spring MVC
     * @return error 405 o 415 con el formato común
     */
    @ExceptionHandler({HttpMediaTypeNotSupportedException.class, HttpRequestMethodNotSupportedException.class})
    public ResponseEntity<ApiError> protocolo(Exception ex) {
        HttpStatus status = HttpStatus.valueOf(((ErrorResponse) ex).getStatusCode().value());
        return error(status, "El método o tipo de contenido no está admitido.", List.of());
    }

    /**
     * Informa qué campos incumplen el contrato sin devolver sus valores.
     * @param ex errores de Bean Validation
     * @return error 400 estructurado
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validacion(MethodArgumentNotValidException ex) {
        List<String> detalles = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage()).sorted().toList();
        return error(HttpStatus.BAD_REQUEST, "La solicitud contiene datos inválidos.", detalles);
    }

    /**
     * Rechaza JSON malformado y campos que no pertenecen al registro.
     * @return error 400 sin fragmentos del cuerpo recibido
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> cuerpoInvalido() {
        return error(HttpStatus.BAD_REQUEST, "El cuerpo JSON es inválido o contiene campos no admitidos.", List.of());
    }

    /**
     * Traduce la duplicidad detectada antes de persistir.
     * @param ex conflicto de correo
     * @return error 409
     */
    @ExceptionHandler(EmailDuplicadoException.class)
    public ResponseEntity<ApiError> duplicado(EmailDuplicadoException ex) {
        return error(HttpStatus.CONFLICT, ex.getMessage(), List.of());
    }

    /**
     * Mantiene el conflicto 409 cuando la restricción única resuelve una carrera.
     * @return respuesta segura sin SQL ni mensaje del controlador MySQL
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> integridad() {
        return error(HttpStatus.CONFLICT, "El registro entra en conflicto con los datos existentes.", List.of());
    }

    /**
     * Oculta detalles internos de un fallo inesperado.
     * @return error 500 con el formato común
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> inesperado() {
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo completar la operación.", List.of());
    }

    /**
     * Construye el formato de error utilizado por la API.
     * @param status estado HTTP
     * @param mensaje explicación segura
     * @param detalles validaciones sin valores recibidos
     * @return respuesta estructurada
     */
    private ResponseEntity<ApiError> error(HttpStatus status, String mensaje, List<String> detalles) {
        return ResponseEntity.status(status).body(new ApiError(
                Instant.now(), status.value(), status.getReasonPhrase(), mensaje, detalles));
    }
}
