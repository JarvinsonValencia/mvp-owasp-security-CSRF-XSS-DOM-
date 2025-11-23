from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import os
from datetime import timedelta

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
CORS(app, supports_credentials=True)

DATABASE = 'users.db'

# ============================================
# DATABASE SETUP
# ============================================
def init_db():
    """Inicializar base de datos con usuarios de prueba"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(100) UNIQUE NOT NULL,
            hash_password VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Usuarios de prueba
    test_users = [
        ('admin@example.com', 'password123', 'admin'),
        ('user@example.com', 'password123', 'user'),
        ('victim@example.com', 'password123', 'user')
    ]
    
    for email, password, role in test_users:
        try:
            hashed = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (email, hash_password, role) VALUES (?, ?, ?)',
                (email, hashed, role)
            )
        except sqlite3.IntegrityError:
            pass  # Usuario ya existe
    
    conn.commit()
    conn.close()
    print("✓ Base de datos inicializada")

def get_db():
    """Obtener conexión a la base de datos"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# STATIC FILES - SERVIR HTML
# ============================================
@app.route('/')
def index():
    """Servir página de login"""
    return send_file('../frontend/index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Servir archivos estáticos (HTML, CSS, JS)"""
    import os
    
    # Obtener directorio base del proyecto
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Intentar en frontend primero
    frontend_path = os.path.join(base_dir, 'frontend', path)
    print(f"🔍 Buscando en frontend: {frontend_path}")
    print(f"   ¿Existe?: {os.path.exists(frontend_path)}")
    if os.path.exists(frontend_path):
        print(f"✅ Sirviendo desde frontend: {path}")
        return send_file(frontend_path)
    
    # Luego intentar en attack
    attack_path = os.path.join(base_dir, 'attack', path)
    print(f"🔍 Buscando en attack: {attack_path}")
    print(f"   ¿Existe?: {os.path.exists(attack_path)}")
    if os.path.exists(attack_path):
        print(f"✅ Sirviendo desde attack: {path}")
        return send_file(attack_path)
    
    # Si no existe, retornar 404
    print(f"❌ Archivo no encontrado: {path}")
    return jsonify({'error': f'Archivo no encontrado: {path}'}), 404

# ============================================
# ENDPOINTS - AUTENTICACIÓN
# ============================================
@app.route('/api/login', methods=['POST'])
def login():
    """Endpoint de login"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email y password requeridos'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['hash_password'], password):
        session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']
        
        # CSRF token para versión segura
        session['csrf_token'] = secrets.token_hex(32)
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'role': user['role']
            },
            'csrf_token': session['csrf_token']
        })
    
    return jsonify({'error': 'Credenciales inválidas'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Cerrar sesión"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/session', methods=['GET'])
def check_session():
    """Verificar sesión actual"""
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': session['user_id'],
                'email': session['email'],
                'role': session['role']
            },
            'csrf_token': session.get('csrf_token')
        })
    return jsonify({'authenticated': False}), 401

# ============================================
# VULNERABLE ENDPOINT - CSRF
# ============================================
@app.route('/api/profile/email', methods=['POST'])
def update_email_vulnerable():
    """
    ❌ VULNERABLE A CSRF
    No valida token CSRF
    """
    if 'user_id' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    data = request.get_json()
    new_email = data.get('email')
    
    if not new_email:
        return jsonify({'error': 'Email requerido'}), 400
    
    # ❌ NO HAY VALIDACIÓN DE CSRF TOKEN
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            (new_email, session['user_id'])
        )
        conn.commit()
        
        # Actualizar sesión
        session['email'] = new_email
        
        return jsonify({
            'success': True,
            'message': f'Email actualizado a {new_email}'
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'El email ya está en uso'}), 400
    finally:
        conn.close()

# ============================================
# SECURE ENDPOINT - CSRF MITIGADO
# ============================================
@app.route('/api/profile/email/secure', methods=['POST'])
def update_email_secure():
    """
    ✅ PROTEGIDO CONTRA CSRF
    Valida token CSRF
    """
    if 'user_id' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    
    data = request.get_json()
    new_email = data.get('email')
    csrf_token = data.get('csrf_token')
    
    if not new_email:
        return jsonify({'error': 'Email requerido'}), 400
    
    # ✅ VALIDACIÓN DE CSRF TOKEN
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'error': 'Token CSRF inválido o ausente'}), 403
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            (new_email, session['user_id'])
        )
        conn.commit()
        
        session['email'] = new_email
        
        return jsonify({
            'success': True,
            'message': f'Email actualizado a {new_email} (CSRF protegido)'
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'El email ya está en uso'}), 400
    finally:
        conn.close()

# ============================================
# MAIN
# ============================================
if __name__ == '__main__':
    # Cambiar al directorio backend para que las rutas relativas funcionen
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    if not os.path.exists(DATABASE):
        init_db()
    
    print("=" * 50)
    print("🚀 MVP OWASP - Servidor iniciado")
    print("=" * 50)
    print("📍 URL: http://localhost:5000")
    print("\n👥 Usuarios de prueba:")
    print("   • admin@example.com : password123 (admin)")
    print("   • user@example.com : password123 (user)")
    print("   • victim@example.com : password123 (user)")
    print("\n🔓 Endpoints vulnerables:")
    print("   • POST /api/profile/email (CSRF)")
    print("   • /search.html (XSS DOM)")
    print("\n🔒 Endpoints seguros:")
    print("   • POST /api/profile/email/secure (CSRF mitigado)")
    print("   • /search-secure.html (XSS DOM mitigado)")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
