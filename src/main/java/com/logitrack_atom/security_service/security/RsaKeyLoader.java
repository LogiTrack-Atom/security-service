package com.logitrack_atom.security_service.security;

import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Carga un par RSA local y verifica su tamaño y correspondencia antes de arrancar.
 *
 * <p>No consulta URLs remotas, no genera claves de respaldo y no incluye el PEM
 * en mensajes de error. La privada se conserva únicamente en memoria del emisor.</p>
 *
 * @author MaxDz
 * @version 0.2.0
 */
@Component
public class RsaKeyLoader {
    /** Crea el cargador de archivos criptográficos externos. */
    public RsaKeyLoader() { }

    /**
     * Carga privada PKCS#8 y pública X.509 de al menos 2048 bits.
     * @param privateLocation archivo local de la clave privada
     * @param publicLocation archivo local de la clave pública
     * @return par comprobado mediante firma y verificación
     * @throws IllegalStateException si el par no es local, válido o correspondiente
     */
    public KeyPair cargar(Resource privateLocation, Resource publicLocation) {
        try {
            if (!"file".equals(privateLocation.getURI().getScheme())
                    || !"file".equals(publicLocation.getURI().getScheme())) {
                throw new IllegalArgumentException();
            }
            RSAPrivateKey privateKey;
            RSAPublicKey publicKey;
            try (var input = privateLocation.getInputStream()) {
                privateKey = RsaKeyConverters.pkcs8().convert(input);
            }
            try (var input = publicLocation.getInputStream()) {
                publicKey = RsaKeyConverters.x509().convert(input);
            }
            if (privateKey == null || publicKey == null || publicKey.getModulus().bitLength() < 2048
                    || !privateKey.getModulus().equals(publicKey.getModulus())) {
                throw new IllegalArgumentException();
            }
            byte[] challenge = "LogiTrack: verificacion de claves".getBytes(StandardCharsets.US_ASCII);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(challenge);
            byte[] signed = signature.sign();
            signature.initVerify(publicKey);
            signature.update(challenge);
            if (!signature.verify(signed)) throw new IllegalArgumentException();
            return new KeyPair(publicKey, privateKey);
        } catch (Exception ex) {
            throw new IllegalStateException("No se pudieron cargar las claves RSA locales: verificar formato, permisos y correspondencia.");
        }
    }
}
