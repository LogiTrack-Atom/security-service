# Renovación del navegador — security-service#11

Decisión del equipo del 10/11/2026: conservar sesión al recargar mediante renovación
segura, sin guardar el JWT en Web Storage. Complementa frontend#3 y el ADR de
shipment-service#71. No se atribuye una aprobación individual del profesor.

El login Bearer anterior (`POST /api/v1/auth/login`) sigue disponible para clientes
API y no emite cookies. Los endpoints del navegador son:

| Método/ruta en Security | Resultado |
|---|---|
| POST `/api/v1/auth/session` | Credenciales JSON; 200 TokenResponse y cookie |
| POST `/api/v1/auth/session/refresh` | Rota cookie; 200 TokenResponse o 401 y cookie eliminada |
| POST `/api/v1/auth/session/logout` | Revoca renovación; 204 y cookie eliminada |

Gateway conserva el prefijo `/applications/apisecurity`. Los tres endpoints exigen
`Origin` exactamente igual a `SESSION_ORIGIN` y `X-LogiTrack-Session: 1`. Se rechaza
`Sec-Fetch-Site: cross-site`. El origen se configura explícitamente; no se deduce de
Host o Forwarded recibidos. La cabecera no simple, el control de origen y SameSite
protegen contra CSRF; no se habilita CORS con cookies entre orígenes. La UI usa
Nginx del mismo origen. Login Bearer y el resto del negocio siguen sin cookies.

Cookie `__Host-logitrack_refresh`: HttpOnly, Secure, SameSite=Strict, Path=/ y sin
Domain. HTTPS es obligatorio en despliegue. HTTP solo se admite en la configuración
para `localhost` de pruebas: Chromium permite ahí cookies Secure; Safari puede
requerir HTTPS incluso en localhost. No existe una opción para quitar Secure.

La credencial opaca combina un selector UUID aleatorio y 256 bits aleatorios. Solo
se persiste su SHA-256. Cada familia tiene límite absoluto `SESSION_TTL` (8h por
defecto, máximo 24h), que no se prorroga al rotar. El JWT se limita a su TTL normal
y al tiempo restante de la familia. La base usa bloqueo pesimista por familia para
serializar rotación/logout. Los hashes consumidos identifican reutilizaciones:
reusar uno revoca la familia y esa revocación se confirma aun devolviendo 401.
Un secreto aleatorio incorrecto no revoca una familia ajena por conocer su selector.

La UI mantiene el JWT en memoria y consulta me antes de habilitar acceso. Al recargar
rota la cookie y recupera el perfil. No renueva después de un 401/403 de negocio ni
reintenta escrituras. Exp de UI termina la sesión; no se suma el skew del servidor.
Logout invalida renovación, pero un Bearer copiado puede seguir válido hasta exp.
La UI serializa intercambios de cookie, usa Web Locks entre pestañas cuando están
disponibles y descarta resultados cancelados/anteriores. Si dos clientes reutilizan
realmente el mismo token, la familia se revoca y se requiere login.

## Migración y operación

Aplicar `docker/mysql/init/002-refresh-sessions.sql` después de 001 a la base de
Security, mediante una conexión administrativa privada, antes de iniciar la imagen
nueva. Es aditivo e idempotente: no borra ni modifica usuarios. En volúmenes vacíos
MySQL ejecuta ambos archivos de init. No usar down --volumes para actualizar una base.
Los archivos SQL de shipment-service/Compose deben coincidir con esta migración.

Conservar pares de claves JWT y volúmenes entre recreaciones. Para mantenimiento,
un operador puede eliminar familias cuyo expires_at ya pasó; la FK elimina sus
hashes consumidos por cascada. No registrar Cookie, Set-Cookie, Authorization,
contraseñas o cuerpos de login/renovación. No exponer entidades o Grant como JSON.

## Verificación

`BrowserSessionIT` usa filtros HTTP y MySQL reales: atributos de cookie, hashes,
rotación, vida absoluta, replay confirmado, concurrencia, expiración, logout, CSRF,
secreto incorrecto y cookies ambiguas. `SessionPropertiesTest` limita origen/TTL.
Las pruebas previas de login Bearer siguen vigentes. Javadoc/doclint aprobado.

`scripts/verify_browser_session.py` prueba la API por Gateway/Nginx en localhost:
credenciales ficticias solo por `S04_ADMIN_EMAIL`/`S04_ADMIN_PASSWORD`, origen local
por `S04_BASE_URL`. 11 solicitudes y 17 aserciones. No valida las decisiones de
CookieJar de un navegador: esa parte se comprobó con el navegador real por separado,
con login → recarga autenticada → logout → recarga en login. El núcleo existente
volvió a pasar 8 escenarios, 38 solicitudes y 57 aserciones con login Bearer.

Referencias: [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html),
[OWASP sesión](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
