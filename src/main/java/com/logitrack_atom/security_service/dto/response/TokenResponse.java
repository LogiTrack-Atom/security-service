package com.logitrack_atom.security_service.dto.response;

/**
 * Entrega el token de acceso y su duración sin repetir credenciales de usuario.
 *
 * @param accessToken JWT firmado que debe enviarse mediante Authorization Bearer
 * @param tokenType tipo de token, Bearer
 * @param expiresIn duración en segundos desde la emisión
 * @author MaxDz
 * @version 0.2.0
 */
public record TokenResponse(String accessToken, String tokenType, long expiresIn) {
    /**
     * Evita que el token termine en logs mediante la representación del DTO.
     * @return tipo y duración con token protegido
     */
    @Override
    public String toString() {
        return "TokenResponse[accessToken=protegido, tokenType=" + tokenType + ", expiresIn=" + expiresIn + "]";
    }
}
