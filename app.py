import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
from datetime import datetime

# -------------------- CONFIGURACIÓN --------------------
app = Flask(__name__)
app.secret_key = 'clave_secreta_segura'
DATABASE = 'cajero.db'

# -------------------- FUNCIONES AUXILIARES --------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db()
    c = conn.cursor()

    # Tabla de usuarios
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    balance REAL DEFAULT 0
                )''')

    # Tabla de transacciones
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    type TEXT,
                    amount REAL,
                    timestamp TEXT,
                    description TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')

    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password, hashed):
    return hash_password(password) == hashed

# -------------------- RUTAS --------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('✅ Cuenta creada correctamente. Inicia sesión.')
            return redirect(url_for('index'))
        except:
            flash('⚠️ El usuario ya existe.')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and check_password(password, user['password']):
        session['user_id'] = user['id']
        return redirect(url_for('dashboard'))
    else:
        flash('❌ Usuario o contraseña incorrectos.')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    return render_template('dashboard.html', user=user)

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if request.method == 'POST':
        amount = float(request.form['amount'])
        new_balance = user['balance'] + amount

        conn.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
        conn.execute(
            "INSERT INTO transactions (user_id, type, amount, timestamp, description) VALUES (?, 'Depósito', ?, ?, ?)",
            (session['user_id'], amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Depósito realizado')
        )
        conn.commit()
        conn.close()

        flash(f"💰 Depósito de ${amount:.2f} exitoso.")
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('deposit.html', user=user)

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if request.method == 'POST':
        amount = float(request.form['amount'])
        if amount > user['balance']:
            flash('⚠️ Fondos insuficientes.')
        else:
            new_balance = user['balance'] - amount
            conn.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
            conn.execute(
                "INSERT INTO transactions (user_id, type, amount, timestamp, description) VALUES (?, 'Retiro', ?, ?, ?)",
                (session['user_id'], amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Retiro realizado')
            )
            conn.commit()
            flash(f"💵 Retiro de ${amount:.2f} exitoso.")
        conn.close()
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('withdraw.html', user=user)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    conn = get_db()
    transactions = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('history.html', transactions=transactions)

@app.route('/logout')
def logout():
    session.clear()
    flash('👋 Sesión cerrada correctamente.')
    return redirect(url_for('index'))

# -------------------- EJECUCIÓN --------------------
if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
