# Configuración remota y ejecución del componente

Security conserva Java 25 y Spring Boot 4.1.1. Importa el BOM Spring Cloud 2025.1.4 y utiliza Config Client mediante `spring.config.import`. No usa `bootstrap.yml` ni desactiva el verificador de compatibilidad.

## Perfiles y origen

| Perfil | Origen | Uso |
| --- | --- | --- |
| dev | Config Server y security-service-dev.yml | Desarrollo integrado; predeterminado |
| prod | Config Server y security-service-prod.yml | Entrega y despliegue |
| local | application-local.yaml | Ejecución explícita sin Config Server |
| test | Recursos y propiedades aisladas de pruebas | Regresión sin el servidor del equipo |

Dev y prod requieren que Config Server responda al iniciar; no usan `optional:` ni un fallback local. Se mantienen `spring.application.name=security-service`, `CONFIG_LABEL=develop` y `CONFIG_SERVER_URL=http://localhost:8085` como valores iniciales del arranque. Para la entrega se selecciona una etiqueta inmutable del repositorio de configuraciones y se registra su commit.

```bash
SPRING_PROFILES_ACTIVE=dev \
CONFIG_SERVER_URL=http://localhost:8085 \
CONFIG_LABEL=develop \
./mvnw spring-boot:run
```

Los timeouts de conexión y lectura de Config Client son 2 y 3 segundos. El contexto no termina de arrancar si no puede cargar la configuración, conectarse a su MySQL o leer sus claves externas. Cambiar propiedades remotas requiere reiniciar este componente; no se habilitan refresh ni endpoints de diagnóstico.

## Contrato para configserver-ms

DiazGab mantiene los YAML de dev/prod en configserver-ms y la aplicación del servidor en configserver. Este documento describe lo que consume security, sin trasladar esos cambios a este repositorio.

| Propiedad remota | Valor o regla |
| --- | --- |
| spring.application.name | security-service |
| server.port | 8082 en ambos ambientes; coincide con EXPOSE y healthcheck |
| spring.datasource.url / username / password | `${DB_URL}`, `${DB_USERNAME}`, `${DB_PASSWORD}`, sin secretos por defecto |
| spring.jpa.open-in-view | false |
| spring.jpa.hibernate.ddl-auto | validate |
| spring.jackson.deserialization.fail-on-unknown-properties | true |
| spring.jackson.datatype.enum.fail-on-numbers-for-enums | true; sintaxis de Jackson 3 |
| server.error.include-message / include-binding-errors / include-stacktrace | never |
| logitrack.security.issuer / audience | logitrack-security / logitrack-api por defecto |
| logitrack.security.access-token-ttl / clock-skew | 15m / 60s iniciales; límites 900 s y 60 s |
| logitrack.security.private-key-location / public-key-location | `${JWT_PRIVATE_KEY_LOCATION}` / `${JWT_PUBLIC_KEY_LOCATION}` |
| logitrack.bootstrap-admin.enabled / email / password | `${BOOTSTRAP_ADMIN_ENABLED:false}`, `${BOOTSTRAP_ADMIN_EMAIL:}`, `${BOOTSTRAP_ADMIN_PASSWORD:}` |
| logitrack.config.marker | security-service-dev o security-service-prod; obligatorio, no sensible |
| logging.level.root / logging.level.com.logitrack_atom | Diferenciados por ambiente; sin registrar credenciales, cuerpos ni tokens |
| management.endpoints.web.exposure.include | health |
| management.endpoint.health.show-details / show-components | never |

Los placeholders de secretos deben mantenerse en la respuesta JSON de Config Server y resolverse únicamente desde el entorno del cliente. No se incorporan valores reales, PEM ni tokens al repositorio de configuraciones. Las rutas `file:` de claves son referencias a archivos montados; no contienen el material criptográfico.

Las entradas de `src/test/resources/config-repository/` son fixtures de prueba. Su perfil prod usa 10 minutos de TTL para demostrar que el bean consume un valor distinto del de dev; no prescribe ese valor para el repositorio del equipo. Los valores operativos iniciales continúan siendo los del contrato compartido.

## Imagen Docker

```bash
docker build -t logitrack-security:0.2.0-local .
```

El Dockerfile utiliza dos etapas y bases oficiales Eclipse Temurin fijadas por digest. La etapa de compilación usa Maven Wrapper; el runtime contiene la aplicación y una sonda de salud Java, sin Maven ni herramientas HTTP adicionales. El usuario predeterminado es 10001:10001. Las pruebas se ejecutan antes de construir; el build de la imagen omite su ejecución y no necesita Docker dentro del contenedor de compilación.

El contexto permite únicamente Maven Wrapper, pom.xml y src/main. Excluye Git, pruebas, documentación, target, archivos de entorno, directorios de claves y extensiones de material criptográfico. Ningún secreto se suministra mediante ARG, ENV del Dockerfile o COPY. Las credenciales de ejecución se entregan externamente.

Para una comprobación local, primero deben estar disponibles MySQL y Config Server. Preparar un archivo de entorno **fuera del repositorio**, usando los nombres de `.env.example`. Sus URLs deben ser accesibles desde Docker: los nombres de servicios para una red compartida, o `host.docker.internal` y los puertos publicados si se ejecutan en el host. `localhost` dentro de security identifica su propio contenedor.

```bash
docker run --rm --name logitrack-security \
  --user "$(id -u):$(id -g)" \
  --add-host host.docker.internal:host-gateway \
  --publish 127.0.0.1:8082:8082 \
  --env-file /ruta/externa/security.env \
  --env JWT_PRIVATE_KEY_LOCATION=file:/run/secrets/jwt-private.pem \
  --env JWT_PUBLIC_KEY_LOCATION=file:/run/secrets/jwt-public.pem \
  --mount type=bind,src=/ruta/externa/jwt-private.pem,dst=/run/secrets/jwt-private.pem,readonly \
  --mount type=bind,src=/ruta/externa/jwt-public.pem,dst=/run/secrets/jwt-public.pem,readonly \
  logitrack-security:0.2.0-local
```

La variante local anterior conserva el UID del propietario de archivos 0600 sin ejecutar la aplicación como root. En un despliegue con el usuario predeterminado se deben aprovisionar los secretos para que UID/GID 10001 pueda leerlos y los demás usuarios no puedan acceder a la privada; no se amplían sus permisos a lectura pública. Montar archivos individuales evita copiar las claves al contenedor o depender de permisos de un directorio del host.

`GET /actuator/health` es público y muestra salud agregada, sin componentes ni detalles; puede incluir los nombres de grupos liveness/readiness que expone la versión de Actuator. Las rutas env, configprops, beans, loggers y heapdump permanecen denegadas. El HEALTHCHECK consulta ese endpoint en loopback:8082 con límites de conexión y lectura; el resto de la API conserva sus reglas de autenticación y autorización.

La etiqueta local no representa una publicación en Docker Hub. La publicación versionada y el Compose general se coordinan desde shipment-service.

## Verificación y cierre

`./mvnw -B -ntp verify javadoc:javadoc` ejecuta la regresión y las pruebas remotas. Estas últimas levantan un Config Server real conectado a Git temporal, comprueban dev/prod y placeholders, y rechazan arranques sin servidor, sin clave privada o sin contraseña de MySQL. El Config Server de prueba y sus dependencias tienen scope test y no forman parte del JAR o de la imagen de producción.

El workflow de PR hacia develop ejecuta esa misma verificación con Java 25 y MySQL aislado. No requiere secretos ni el Config Server del equipo.

La issue #4 requiere además repetir la integración contra las versiones entregadas de configserver y configserver-ms, registrar sus commits y comprobar los dos perfiles con la imagen. Las pruebas temporales permiten desarrollar el cliente y el contenedor mientras esos componentes avanzan; no se registran como evidencia de una entrega del equipo todavía pendiente.

## Referencias

- [Compatibilidad de Spring Cloud](https://spring.io/projects/spring-cloud/).
- [Spring Cloud 2025.1.4](https://spring.io/blog/2026/10/23/spring-cloud-2025-1-4-has-been-released/).
- [Config Client y Config Data](https://docs.spring.io/spring-cloud-config/reference/client.html).
- [Configuración de Jackson en Spring Boot](https://docs.spring.io/spring-boot/how-to/spring-mvc.html).

## Integración con los componentes del equipo — 27/10/2026

Se verificó la imagen de security contra el Config Server de
[este commit](https://github.com/LogiTrack-Atom/configserver/commit/60d9d8f291faedecf7c65e6dc682673f13ed3622)
y las propiedades de
[esta revisión](https://github.com/LogiTrack-Atom/configserver-ms/commit/8a1ff95eab2b7ee025822ee52ff8892d9b40518a).
El servidor se compiló desde su código y se ejecutó como JAR sobre una JRE en
contenedor aislado, leyendo GitHub directamente; no se utilizó el fixture de pruebas.
Esta comprobación no sustituye la construcción de su futura imagen Docker propia.

Ambos perfiles alcanzaron healthy y permitieron login, perfil autenticado y
alta/consulta administrativa. Conservaron TTL de 900 segundos, diferenciaron
marcadores y logging, y rechazaron rol numérico, rol en registro público, contraseña
incorrecta, solicitudes sin token y diagnósticos. Config Server devolvió los
placeholders de secretos sin resolver, incluso con una variable trampa de DB_PASSWORD
en su entorno. Los arranques sin servidor, sin privada, sin pública o sin contraseña
de MySQL terminaron con error. Se retiraron los contenedores, red y secretos de prueba.

La revisión original de propiedades omitía la clave pública y reproducía un fallo
de arranque. El ajuste se registra en
[configserver-ms#6](https://github.com/LogiTrack-Atom/configserver-ms/pull/6).
La imagen ejecutada contiene el código de security del commit
`88c4ae8aa5158a4c4ea5febc7c780adbd12e2ce4`; la actualización posterior de esta guía
solo corrige nombres de archivos, marcadores y el registro de la comprobación.
