package com.logitrack_atom.security_service.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Limita la longitud codificada de una contraseña para evitar truncamientos BCrypt.
 *
 * @author MaxDz
 * @version 0.1.0
 * @see MaxUtf8BytesValidator
 */
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = MaxUtf8BytesValidator.class)
public @interface MaxUtf8Bytes {
    /**
     * Define el límite de longitud codificada.
     * @return límite de bytes UTF-8 admitidos
     */
    int value();
    /**
     * Define el mensaje que recibirá el cliente cuando se supere el límite.
     * @return mensaje seguro de validación, sin el valor recibido
     */
    String message() default "no puede superar {value} bytes UTF-8";
    /**
     * Define los grupos a los que pertenece esta restricción.
     * @return grupos de validación
     */
    Class<?>[] groups() default {};
    /**
     * Define la información adicional asociada a la restricción.
     * @return metadatos de validación
     */
    Class<? extends Payload>[] payload() default {};
}
