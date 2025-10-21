import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
DATABASE = 'users.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_user_table():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_user_table()

EMAIL_REGEX = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    if not (email and password):
        return jsonify({"error": "Thiếu email hoặc mật khẩu"}), 400
    if not EMAIL_REGEX.match(email):
        return jsonify({"error": "Email không hợp lệ"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu phải từ 6 ký tự"}), 400

    conn = get_db()
    c = conn.cursor()
    try:
        hashed_pw = generate_password_hash(password)
        c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_pw))
        conn.commit()
        return jsonify({"message": "Đăng ký thành công"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email đã tồn tại"}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    if not (email and password):
        return jsonify({"error": "Thiếu email hoặc mật khẩu"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        # Có thể tạo JWT hoặc session ở đây, demo trả về success
        return jsonify({"message": "Đăng nhập thành công", "email": email}), 200
    else:
        return jsonify({"error": "Email hoặc mật khẩu không đúng"}), 401

if __name__ == '__main__':
    app.run(debug=True)
