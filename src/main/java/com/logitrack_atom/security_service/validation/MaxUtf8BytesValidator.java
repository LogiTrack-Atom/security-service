package com.logitrack_atom.security_service.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.nio.charset.StandardCharsets;

/**
 * Valida el tamaño real en bytes de cadenas sin modificar su contenido.
 *
 * @author MaxDz
 * @version 0.1.0
 */
public class MaxUtf8BytesValidator implements ConstraintValidator<MaxUtf8Bytes, String> {
    /** Crea el validador utilizado por Bean Validation. */
    public MaxUtf8BytesValidator() { }

    private int limit;

    /** {@inheritDoc} */
    @Override
    public void initialize(MaxUtf8Bytes annotation) { limit = annotation.value(); }

    /** {@inheritDoc} */
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value == null || value.getBytes(StandardCharsets.UTF_8).length <= limit;
    }
}
