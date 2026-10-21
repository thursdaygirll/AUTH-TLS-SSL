# backend-auth-tls

Spring Boot 3.2 REST API with JWT Bearer authentication and mutual SSL/TLS on port 8443.

---

## Prerequisites

| Tool | Version |
|------|---------|
| Java JDK | 21+ |
| Maven | 3.9+ |
| keytool | (bundled with JDK) |

---

## Step 1 — Generate the TLS keystore

Run this command **once** from the project root.  
It creates a PKCS12 keystore inside `src/main/resources/` so Spring Boot can find it on the classpath.

```bash
keytool -genkeypair \
  -alias backend-auth-tls \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -storetype PKCS12 \
  -keystore src/main/resources/keystore.p12 \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=localhost, OU=Dev, O=UTCH, L=Ciudad Juarez, ST=Chihuahua, C=MX"
```

After generating the keystore, **uncomment** the following line in `src/main/resources/application.yml`:

```yaml
server:
  ssl:
    key-store: classpath:keystore.p12   # <-- uncomment this line
```

> **Note:** The keystore file is intentionally excluded from version control (add `*.p12` to `.gitignore`).  
> Never commit private keys to a repository.

---

## Step 2 — Build and run

```bash
# Build (skip tests on first run if keystore is not yet generated)
mvn clean package -DskipTests

# Run
mvn spring-boot:run
```

The application starts at: **https://localhost:8443**

> Because the certificate is self-signed, browsers and curl will warn about it.  
> Pass `-k` / `--insecure` to curl during development, or import the certificate into your trust store.

---

## Step 3 — Test the API with curl

All examples below use `-k` to bypass self-signed certificate validation.

### 3.1 Public endpoint (no auth needed)

```bash
curl -k https://localhost:8443/api/public/info
```

Expected response:

```json
{
  "message": "This is a public endpoint. No authentication required.",
  "timestamp": "2025-..."
}
```

---

### 3.2 Login (get a JWT)

```bash
curl -k -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Expected response (200):

```json
{
  "token": "<jwt-token>",
  "tokenType": "Bearer",
  "username": "admin",
  "expiresInMs": 3600000
}
```

Save the token value — you will use it in the next step.

```bash
# Convenience: capture the token in a shell variable
TOKEN=$(curl -sk -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

---

### 3.3 Register a new user

```bash
curl -k -X POST https://localhost:8443/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"secret99"}'
```

Expected response (201 Created).

---

### 3.4 Access the protected endpoint

```bash
curl -k https://localhost:8443/api/hello \
  -H "Authorization: Bearer $TOKEN"
```

Expected response (200):

```json
{
  "message": "Hello, admin! You are authenticated.",
  "username": "admin",
  "roles": ["ROLE_USER", "ROLE_ADMIN"],
  "timestamp": "2025-..."
}
```

---

### 3.5 Access without a token (expect 401)

```bash
curl -k https://localhost:8443/api/hello
```

Expected response (401):

```json
{
  "timestamp": "...",
  "status": 401,
  "error": "Unauthorized",
  "message": "Authentication is required to access this resource. ...",
  "path": "/api/hello"
}
```

---

### 3.6 Login with bad credentials (expect 401)

```bash
curl -k -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpassword"}'
```

---

## Hard-coded in-memory users

| Username | Password  | Roles            |
|----------|-----------|------------------|
| admin    | admin123  | ROLE_USER, ROLE_ADMIN |
| user     | user123   | ROLE_USER        |

These users exist for the lifetime of the running process.  
New users registered via `/api/auth/register` are also kept in memory only and are lost on restart.

---

## Security configuration summary

| Setting | Value |
|---------|-------|
| HTTPS port | 8443 |
| TLS protocols | TLSv1.2, TLSv1.3 |
| JWT algorithm | HS256 |
| JWT expiry | 1 hour (configurable via `jwt.expiration-ms`) |
| Session policy | Stateless (no server-side sessions) |
| CSRF | Disabled (REST API) |
| CORS allowed origin | http://localhost:4200 |
| Public routes | /api/auth/**, /api/public/** |
| Protected routes | all others |

---

## Project structure

```
backend-auth-tls/
├── pom.xml
├── README.md
└── src/main/
    ├── resources/
    │   └── application.yml
    └── java/com/utch/backendauth/
        ├── BackendAuthApplication.java
        ├── config/
        │   ├── JwtConfig.java
        │   └── SecurityConfig.java
        ├── controller/
        │   ├── AuthController.java
        │   └── HelloController.java
        ├── dto/
        │   ├── AuthRequest.java
        │   └── AuthResponse.java
        ├── security/
        │   ├── CustomAccessDeniedHandler.java
        │   ├── CustomAuthEntryPoint.java
        │   ├── JwtAuthenticationFilter.java
        │   └── JwtUtil.java
        └── service/
            └── UserDetailsServiceImpl.java
```
