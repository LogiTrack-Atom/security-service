package com.logitrack_atom.security_service.service;

import com.logitrack_atom.security_service.config.SessionProperties;
import com.logitrack_atom.security_service.dto.request.LoginRequest;
import com.logitrack_atom.security_service.dto.response.TokenResponse;
import com.logitrack_atom.security_service.entity.*;
import com.logitrack_atom.security_service.exception.CredencialesInvalidasException;
import com.logitrack_atom.security_service.repository.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Renueva tokens con rotación atómica y revocación de familia ante reutilización. */
@Service
@EnableConfigurationProperties(SessionProperties.class)
public class BrowserSessionService {
    private final AuthService auth;
    private final UsuarioRepository users;
    private final JwtTokenService jwt;
    private final RefreshSessionRepository sessions;
    private final ConsumedRefreshTokenRepository consumed;
    private final SessionProperties policy;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    /** Resultado interno; el refresh solo se envía mediante Set-Cookie.
     * @param access token de acceso público para el cliente
     * @param refresh credencial efímera, nunca serializar ni registrar
     * @param expiresAt vencimiento absoluto de renovación
     */
    public record Grant(TokenResponse access, String refresh, Instant expiresAt) {
        /** @return representación fija sin credenciales */
        @Override public String toString() { return "Grant[credenciales protegidas]"; }
    }

    /** Inyecta autenticación, persistencia y reloj sin claves de renovación compartidas.
     * @param auth autenticación existente
     * @param users cuentas actuales
     * @param jwt firmante de acceso
     * @param sessions familias de renovación
     * @param consumed hashes consumidos
     * @param policy política externa
     * @param clock reloj UTC
     */
    public BrowserSessionService(AuthService auth, UsuarioRepository users, JwtTokenService jwt,
            RefreshSessionRepository sessions, ConsumedRefreshTokenRepository consumed,
            SessionProperties policy, Clock clock) {
        this.auth = auth; this.users = users; this.jwt = jwt; this.sessions = sessions;
        this.consumed = consumed; this.policy = policy; this.clock = clock;
    }

    /** Inicia una familia independiente después de validar credenciales.
     * @param credentials datos recibidos en login
     * @param previous cookie anterior que se revoca después de autenticar
     * @return acceso y renovación interna
     */
    @Transactional
    public Grant login(LoginRequest credentials, String previous) {
        Usuario user = auth.autenticarCuenta(credentials);
        logout(previous);
        UUID id = UUID.randomUUID(); String refresh = generate(id);
        Instant end = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plus(policy.ttl());
        sessions.save(new RefreshSession(id, user.getId(), digest(refresh), end));
        return new Grant(jwt.emitir(user, end), refresh, end);
    }

    /** Consume un token una sola vez; reutilizar un hash consumido revoca la familia.
     * La excepción 401 no revierte esa revocación.
     * @param token cookie opaca; nunca un JWT
     * @return nueva rotación con el mismo límite absoluto
     */
    @Transactional(noRollbackFor = CredencialesInvalidasException.class)
    public Grant refresh(String token) {
        RefreshSession session = locate(token);
        if (session.isRevoked() || !clock.instant().isBefore(session.getExpiresAt())) {
            session.revoke(); throw new CredencialesInvalidasException();
        }
        String hash = digest(token);
        if (!MessageDigest.isEqual(hash.getBytes(StandardCharsets.US_ASCII), session.getTokenHash().getBytes(StandardCharsets.US_ASCII))) {
            if (consumed.findById(hash).filter(row -> row.getSessionId().equals(session.getId())).isPresent()) session.revoke();
            throw new CredencialesInvalidasException();
        }
        Usuario user = users.findById(session.getUsuarioId()).orElseThrow(CredencialesInvalidasException::new);
        consumed.save(new ConsumedRefreshToken(hash, session.getId()));
        String next = generate(session.getId()); session.rotate(digest(next));
        return new Grant(jwt.emitir(user, session.getExpiresAt()), next, session.getExpiresAt());
    }

    /** Revoca una familia con token actual o un hash consumido de esa misma familia.
     * @param token cookie de renovación; ausente o inválida permite logout local idempotente
     */
    @Transactional
    public void logout(String token) {
        if (token == null || !token.matches("[a-f0-9-]{36}\\.[A-Za-z0-9_-]{43}")) return;
        UUID id;
        try { id = UUID.fromString(token.substring(0, 36)); } catch (IllegalArgumentException invalid) { return; }
        sessions.lockById(id).ifPresent(session -> {
            String hash = digest(token);
            if (hash.equals(session.getTokenHash()) || consumed.findById(hash).filter(row -> row.getSessionId().equals(id)).isPresent()) session.revoke();
        });
    }

    /** Valida el formato antes de consultar la familia con bloqueo.
     * @param token credencial opaca
     * @return fila bloqueada
     */
    private RefreshSession locate(String token) {
        if (token == null || !token.matches("[a-f0-9-]{36}\\.[A-Za-z0-9_-]{43}")) throw new CredencialesInvalidasException();
        try { return sessions.lockById(UUID.fromString(token.substring(0, 36))).orElseThrow(CredencialesInvalidasException::new); }
        catch (IllegalArgumentException invalid) { throw new CredencialesInvalidasException(); }
    }
    /** Genera 256 bits aleatorios además del selector UUID.
     * @param id selector de familia
     * @return token opaco nuevo
     */
    private String generate(UUID id) {
        byte[] secret = new byte[32]; random.nextBytes(secret);
        return id + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    }
    /** Hash unidireccional de una credencial de alta entropía.
     * @param value token que no se persistirá
     * @return hash hexadecimal de longitud fija
     */
    private String digest(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII))); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA-256 no disponible."); }
    }
}
