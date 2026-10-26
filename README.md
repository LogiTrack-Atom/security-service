# security-service

Servicio de identidad de [LogiTrack Atom](https://github.com/LogiTrack-Atom).
Responsable principal: [MaxDZ-10](https://github.com/MaxDZ-10).

## Alcance actual

La aplicación implementa registro CLIENTE, usuarios UUID, contraseñas con hash, bootstrap ADMIN y autenticación JWT RS256. Usa Java 25, Spring Boot 4.1.1 y MySQL 8.4.11. Maven Wrapper fija Maven 3.10.0. Versión del servicio: 0.2.0-SNAPSHOT.

El registro corresponde a la [issue #1](https://github.com/LogiTrack-Atom/security-service/issues/1), y login, JWT y perfil autenticado a la [issue #2](https://github.com/LogiTrack-Atom/security-service/issues/2). La administración REST de usuarios continúa en la [issue #3](https://github.com/LogiTrack-Atom/security-service/issues/3). Config Client y la imagen Docker de la aplicación continúan en la [issue #4](https://github.com/LogiTrack-Atom/security-service/issues/4). Las rutas de administración permanecen denegadas hasta completar sus reglas.

Los [contratos compartidos](https://github.com/LogiTrack-Atom/shipment-service/blob/develop/docs/sprint02/Contratos_tecnicos.md) y el [Project común](https://github.com/orgs/LogiTrack-Atom/projects/1) coordinan los cinco repositorios. El Compose general se mantiene en shipment-service.

## Estructura

| Componente | Responsabilidad |
| --- | --- |
| controller | Frontera HTTP y validación del registro |
| dto | Entrada limitada a email/password y respuestas sin credenciales |
| service / service.impl | Unicidad, hash, rol de alta y transacciones |
| repository / entity | Persistencia y auditoría de usuarios |
| mapper | Conversión a datos públicos |
| config / bootstrap | Seguridad web y alta inicial opcional de ADMIN |
| security | Carga local de claves y validación del contrato JWT |
| exception / validation | ApiError y límites de entrada |
| docker/mysql/init | Esquema inicial versionado |
| src/test | Pruebas unitarias y MySQL aislado mediante Testcontainers |

Las clases y los métodos públicos incluyen Javadoc con reglas, parámetros y retornos aplicables. El UUID de usuario es independiente del UUID de cliente o repartidor; este servicio no contiene relaciones JPA hacia otras bases.

## Registro público

`POST /api/v1/auth/register`, con `Content-Type: application/json`:

```json
{
  "email": "ana@example.com",
  "password": "FraseDeEjemploParaEntornoLocal"
}
```

La contraseña del ejemplo es ilustrativa. La respuesta 201 contiene `id`, `email`, `roles: ["CLIENTE"]`, `createdAt` y `updatedAt`; nunca incluye contraseña ni hash. El rol se decide en el servicio. JSON con `rol`, `roles`, identificadores de dominio u otros campos desconocidos produce 400.

El correo se normaliza con `strip()` y minúsculas mediante `Locale.ROOT`; tiene formato email, máximo 254 caracteres y restricción única en MySQL. La contraseña no se recorta ni normaliza: admite al menos 12 caracteres y hasta 72 bytes UTF-8, comprobados antes de BCrypt para evitar truncamiento de caracteres multibyte. El hash usa BCrypt con factor 12 y prefijo `{bcrypt}`.

| Estado | Significado |
| --- | --- |
| 201 | Cuenta CLIENTE creada |
| 400 | Credenciales inválidas, JSON inválido o campos no admitidos |
| 409 | Correo ocupado o conflicto de persistencia, incluida concurrencia |
| 415 | Tipo de contenido no admitido |
| 401 / 403 | Denegación de una ruta no habilitada |

Los errores mantienen `timestamp`, `status`, `error`, `mensaje` y `detalles`, conforme a ApiError. Las respuestas no devuelven valores de contraseña, SQL ni trazas internas. No se habilitan HTTP Basic, formulario, sesión ni usuario de desarrollo automático de Spring Security.

## Login y usuario autenticado

`POST /api/v1/auth/login` recibe únicamente email y password. El email se normaliza igual que en el registro y la contraseña se verifica sin alterarla. Una cuenta inexistente y una contraseña incorrecta producen el mismo 401 con `mensaje: "Credenciales inválidas."`. También se verifica un hash ficticio cuando no existe la cuenta para conservar el trabajo criptográfico de esa ruta. Una entrada estructuralmente inválida produce 400; el login rechaza roles, sub e identificadores enviados en el cuerpo.

Una autenticación correcta devuelve 200 con este contrato:

```json
{
  "accessToken": "<JWT firmado>",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

`GET /api/v1/auth/me` requiere `Authorization: Bearer <accessToken>` y devuelve los datos públicos de la cuenta identificada por el `sub` validado. Los parámetros de otro usuario no cambian ese objetivo. Una cuenta retirada de la base produce 401. Login y perfil usan `Cache-Control: no-store`; no crean una sesión ni devuelven la contraseña o el hash.

Los tokens contienen UUID de usuario en `sub`, roles persistidos en `roles`, `iss=logitrack-security`, audiencia `logitrack-api` en `aud`, `iat`, `nbf` y `exp`. La duración por defecto es 900 segundos y la tolerancia de reloj es 60 segundos. Los validadores admiten ese margen alrededor de los tiempos de validez; no renuevan ni modifican el token. Se pueden configurar duraciones enteras de 1 a 900 segundos y tolerancias enteras de 0 a 60 segundos.

El decoder permite exclusivamente RS256 y valida firma, emisor, audiencia, tiempos, UUID canónico y roles conocidos. Exige exp e iat y rechaza vidas superiores al límite configurado. Convierte los roles a `ROLE_ADMIN`, `ROLE_CLIENTE` o `ROLE_REPARTIDOR`; Spring Security agrega además el factor de autenticación Bearer. El sub no representa automáticamente un cliente ni un repartidor.

Los tokens vencidos fuera de tolerancia, alterados, sin firma, firmados con otra clave o con algoritmo diferente se rechazan con 401 y ApiError. El token se admite solo en la cabecera Authorization. No se implementan refresh tokens ni discovery OIDC. Para renovar el acceso se realiza un nuevo login. Los demás servicios validarán localmente con la clave pública y los mismos parámetros; no necesitan consultar a security por cada token.

## Claves externas

Para crear un par nuevo se necesita OpenSSL. Desde la raíz del repositorio:

```bash
mkdir -p "$HOME/.local/share/logitrack"
./scripts/generar-claves.sh "$HOME/.local/share/logitrack/jwt-keys"
export JWT_PRIVATE_KEY_LOCATION="file:$HOME/.local/share/logitrack/jwt-keys/jwt-private.pem"
export JWT_PUBLIC_KEY_LOCATION="file:$HOME/.local/share/logitrack/jwt-keys/jwt-public.pem"
```

El script exige un directorio nuevo y genera RSA de 3072 bits con permisos restringidos al propietario. Para reutilizar un par existente se configuran directamente sus ubicaciones, manteniendo la privada PKCS#8 y la pública X.509. El servicio admite RSA desde 2048 bits y comprueba la correspondencia del par al arrancar. Las ubicaciones deben ser archivos locales; no se descargan claves por HTTP ni se generan claves de reemplazo durante el arranque.

Solo security recibe la privada. Shipment y courier recibirán exclusivamente la pública mediante sus archivos montados. Las rutas se suministran por entorno, y `.gitignore` y `.dockerignore` excluyen claves, almacenes y secretos. El repositorio y el JAR no contienen un par privado. La futura imagen Docker se verificará en la issue #4; esta etapa prepara sus exclusiones y el uso de archivos externos.

| Variable | Valor |
| --- | --- |
| JWT_PRIVATE_KEY_LOCATION | URI file: absoluta de la privada, requerida |
| JWT_PUBLIC_KEY_LOCATION | URI file: absoluta de la pública, requerida |
| JWT_ISSUER | logitrack-security por defecto |
| JWT_AUDIENCE | logitrack-api por defecto |
| JWT_ACCESS_TOKEN_TTL | 15m por defecto, máximo 900 segundos |
| JWT_CLOCK_SKEW | 60s por defecto, máximo 60 segundos |

Un cambio de clave pública debe coordinarse con los validadores: los tokens firmados con la clave anterior dejarán de validarse cuando se reemplace esa pública. La rotación y distribución se realizan fuera de Git. Los DTOs de login y token protegen sus representaciones de diagnóstico para que no incluyan credenciales.

## MySQL local y arranque

Se necesitan JDK 25, Docker y acceso a Maven Central durante la primera resolución de dependencias. Los siguientes comandos crean una base local dedicada; los secretos se ingresan por terminal y no se escriben en Git.

Desde la raíz de este repositorio, en Bash:

```bash
read -r -s -p 'Contraseña de security_app: ' MYSQL_PASSWORD
printf '\n'
read -r -s -p 'Contraseña root del MySQL local: ' MYSQL_ROOT_PASSWORD
printf '\n'
export MYSQL_PASSWORD MYSQL_ROOT_PASSWORD

docker run -d --name logitrack-security-mysql \
  -p 127.0.0.1:3309:3306 \
  -e MYSQL_DATABASE=security_db -e MYSQL_USER=security_app \
  -e MYSQL_PASSWORD -e MYSQL_ROOT_PASSWORD \
  --mount type=volume,src=logitrack-security-mysql-data,dst=/var/lib/mysql \
  --mount "type=bind,src=$PWD/docker/mysql/init,dst=/docker-entrypoint-initdb.d,readonly" \
  mysql:8.4.11

export DB_URL='jdbc:mysql://localhost:3309/security_db?serverTimezone=UTC'
export DB_USERNAME=security_app
export DB_PASSWORD="$MYSQL_PASSWORD"
```

Esperar a que MySQL termine la inicialización; puede comprobarse con `docker logs logitrack-security-mysql`. Con las dos variables de ubicación de claves del apartado anterior configuradas:

```bash
./mvnw spring-boot:run
```

La API inicia en el puerto 8082. El script SQL se ejecuta al inicializar un volumen nuevo. En un volumen existente no vuelve a aplicar cambios de esquema: Hibernate usa `ddl-auto=validate` y rechaza divergencias. Los cambios posteriores requieren una migración versionada. No es necesario borrar datos para ejecutar las pruebas.

Para usar un MySQL ya provisto, un administrador crea `security_db`, un usuario exclusivo `security_app` con acceso únicamente a esa base y ejecuta `docker/mysql/init/001-schema.sql` dentro de ella. La aplicación recibe exclusivamente las credenciales de ese usuario. Los secretos están ausentes de `.env.example`; Spring no carga archivos `.env` automáticamente, por lo que deben exportarse las variables o suministrarse con el mecanismo del entorno.

## Primer administrador

El bootstrap está deshabilitado por defecto. Para habilitarlo durante un arranque, después de configurar MySQL:

```bash
read -r -p 'Email del primer administrador: ' BOOTSTRAP_ADMIN_EMAIL
read -r -s -p 'Contraseña del primer administrador: ' BOOTSTRAP_ADMIN_PASSWORD
printf '\n'
export BOOTSTRAP_ADMIN_EMAIL BOOTSTRAP_ADMIN_PASSWORD
BOOTSTRAP_ADMIN_ENABLED=true ./mvnw spring-boot:run
```

Las credenciales deben cumplir el mismo contrato del registro. Si faltan o son inválidas, el arranque falla con un mensaje que no revela la contraseña. Si ya existe ADMIN con ese correo, se conservan UUID, hash y fechas; no se restablece su contraseña. Si el correo pertenece a CLIENTE o REPARTIDOR, el arranque falla y no cambia su rol. Una colisión de unicidad entre instancias concurrentes puede detener una de ellas de forma segura; al reiniciar encuentra el administrador persistido.

Una vez creado, se puede reiniciar con el bootstrap deshabilitado y retirar sus credenciales del entorno. No existe un endpoint público de bootstrap ni una contraseña inicial compartida.

## Verificación

Pruebas unitarias, validación y hash, sin MySQL ni Docker:

```bash
./mvnw clean test
```

Suite completa con MySQL 8.4.11 aislado y el esquema real:

```bash
./mvnw clean verify
```

Testcontainers utiliza un puerto aleatorio y credenciales efímeras de prueba. No usa el MySQL local anterior ni los volúmenes del equipo. Verifica API y filtros reales, restricciones, usuario MySQL limitado, concurrencia, bootstrap, login y perfil JWT; no utiliza transacciones de prueba que oculten el commit. Las claves de las pruebas se generan en un directorio temporal y se retiran al finalizar el proceso, sin utilizar las claves del operador. Ryuk elimina sus contenedores al terminar. Si Docker Desktop no es detectado automáticamente, se puede indicar su socket mediante `DOCKER_HOST`.

Los reportes se generan en `target/surefire-reports` y `target/failsafe-reports`. Mockito declara su agente explícitamente en Surefire y Failsafe; Failsafe también habilita el acceso nativo requerido por Testcontainers en Java 25.

Para verificar y generar Javadoc:

```bash
./mvnw javadoc:javadoc -Ddoclint=all
```

La documentación HTML queda dentro de `target/` y no se versiona. La generación de Javadoc rechaza advertencias y errores de documentación. Los resultados efectivamente ejecutados y el commit verificado se registran en la PR de la issue.

El JAR de esta versión se puede ejecutar con `java -jar target/security-service-0.2.0-SNAPSHOT.jar`, manteniendo las mismas variables de MySQL y claves. Su verificación de arranque no requiere Config Server en esta etapa; la integración centralizada corresponde a la issue #4.

## Colaboración

Las ramas por tarea parten de `develop` y los PR se integran en `develop`. Cada issue se cierra después de verificar aceptación e integración; `main` continúa como rama predeterminada. Se mantienen alineadas las prioridades Alta/Media del Project con las etiquetas priority:P0/P1.
