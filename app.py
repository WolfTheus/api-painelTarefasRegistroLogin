from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
import datetime
import os
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

def create_table_usuarios():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'usuario')''')

    conn.commit()
    conn.close()

def create_table_tarefas():
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS tarefas
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      tarefa TEXT NOT NULL,
                      status TEXT NOT NULL,
                      usuario_id INTEGER NOT NULL,
                      FOREIGN KEY (usuario_id) REFERENCES usuarios (id))''')
    conn.commit()
    conn.close()

def criar_tarefas(usuario_id, tarefa, status):
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tarefas (tarefa, status, usuario_id) VALUES (?, ?, ?)", (tarefa, status, usuario_id))
    conn.commit()
    conn.close()

def login():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE username=?", (request.json['username'],))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user[2], request.json['password']):
        user_id = user[0]
        role = user[3]
        token_payload ={
            'user_id': user_id, 
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'Logado': True, 'token': token, 'refresh_token': gerar_refresh_token(user[0])}), 200
    else:
        return "Nome de usuário ou senha incorretos", 401

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'message': 'Token não fornecido'}), 401
            try:
                decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                user_role = decoded_token.get('role')
                if user_role != required_role:
                    return jsonify({'message': 'Acesso negado, permissão insucifiente.'}), 403
            except jwt.ExpiredSignatureError:
                    return jsonify({'message': 'Token expirado'}), 401
            except jwt.InvalidTokenError:
                    return jsonify({'message': 'Token inválido'}), 401
            
            return f(*args, **kwargs)
        return wrapper
    return decorator
                


def registro():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    hashed_password = generate_password_hash (request.json['password'])
    role = request.json.get('role', 'usuario')
    cursor.execute("INSERT INTO usuarios (username, password, role) VALUES (?, ?, ?)",(request.json['username'], hashed_password, role))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Usuário registrado com sucesso'}), 201

def lookup_user(id):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id=?", (id,))
    user = cursor.fetchone()
    if user:
        user = {
            'id': user[0],
            'username': user[1],
            'hashed_password': user[2],
            'role': user[3]
        }
    else:
        user = None
    conn.close()
    return jsonify(user)

def lookup_tarefasdousuario(id):
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tarefas WHERE usuario_id=?", (id,))
    tarefas = cursor.fetchall()
    conn.close()
    lista_tarefas = [{'id': tarefa[0], 'tarefa': tarefa[1], 'status': tarefa[2], 'usuario_id': tarefa[3]} for tarefa in tarefas]
    tarefasU = {'tarefas': lista_tarefas}
    return jsonify(tarefasU)

def editar_tarefas(id, tarefa, status):
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE tarefas SET tarefa=?, status=? WHERE id=?", (tarefa, status, id))
    conn.commit()
    conn.close()

def delete_tarefas(id):
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tarefas WHERE id=?", (id,))
    conn.commit()
    conn.close()

def gerar_refresh_token(user_id):
    refresh_token = jwt.encode({'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, app.config['SECRET_KEY'])
    return refresh_token

def verificar_refresh_token(token):
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded_token['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    
def refresh_token():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token não fornecido'}), 401
    user_id = verificar_refresh_token(token)
    if user_id:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE id=?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if not user:
            return jsonify({'message': 'Usuário não encontrado'}), 404
        
        role = user[0]
        new_token = jwt.encode({
            'user_id': user_id,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': new_token}), 200
    else:
        return jsonify({'message': 'Token inválido ou expirado'}), 401

@app.route('/criar-tarefas', methods=['POST'])
def handle_criar_tarefas():
    usuario_id = request.json['usuario_id']
    tarefa = request.json['tarefa']
    status = request.json['status']
    criar_tarefas(usuario_id, tarefa, status)
    return jsonify({'message': 'Tarefa criada com sucesso'}), 201

@app.route('/protegido', methods=['GET'])
def protegido():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token não fornecido'}), 401
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return jsonify({'message': 'Acesso permitido', 'user_id': decoded_token['user_id']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token inválido'}), 401         

@app.route('/login', methods=['POST'])
def handle_login():
    return login()

@app.route('/deletar-tarefas', methods=['DELETE'])
def handle_deletar_tarefas():
    tarefa_id = request.json['id']
    delete_tarefas(tarefa_id)
    return jsonify({'message': 'Tarefa deletada com sucesso'}), 200

@app.route('/registro', methods=['POST'])
def handle_register():
    return registro()   

@app.route('/checar-tarefas', methods=['GET'])
def handle_checar_tarefas():
    user_id = request.args.get('id')
    if not user_id or not user_id.isdigit():
        return jsonify({'message': 'ID do usuário inválido ou não fornecido'}), 400
    else:
        return lookup_tarefasdousuario(int(user_id))
    
@app.route('/editar-tarefas', methods=['PUT'])
def handle_editar_tarefas():
    tarefa_id = request.json['id']
    tarefa = request.json['tarefa']
    status = request.json['status']
    editar_tarefas(tarefa_id, tarefa, status)
    return jsonify({'message': 'Tarefa editada com sucesso'}), 200

@app.route('/admin-users', methods=['GET'])
@role_required('admin')
def handle_admin_users():
    user_id = request.args.get('id')
    if not user_id or not user_id.isdigit():
        return jsonify({'message': 'ID do usuário inválido ou não fornecido'}), 400
    else:
        return lookup_user(int(user_id))

@app.route('/create_table_usuarios', methods=['GET'])
def handle_create_table_usuarios():
    create_table_usuarios()
    return "Table created!"

@app.route('/refresh-token', methods=['POST'])
def handle_refresh_token():
    return refresh_token()

if __name__ == '__main__':  
    create_table_usuarios()  # Ensure the table is created before the app starts
    create_table_tarefas()  # Ensure the table is created before the app starts
    app.run(debug=True)
