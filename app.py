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
                      password TEXT NOT NULL)''')

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
        token = jwt.encode({'user_id': user[0], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'message': 'Login bem-sucedido', 'token': token}), 200
    else:
        return "Nome de usuário ou senha incorretos", 401

def registro():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    hashed_password = generate_password_hash (request.json['password'])
    cursor.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)",(request.json['username'], hashed_password))
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
            'hashed_password': user[2]
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
    for tarefa in tarefas:
        tarefa = {
            'id': tarefa[0],
            'tarefa': tarefa[1],
            'status': tarefa[2],
            'usuario_id': tarefa[3]
        }
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

if __name__ == '__main__':  
    create_table_usuarios()  # Ensure the table is created before the app starts
    create_table_tarefas()  # Ensure the table is created before the app starts
    app.run(debug=True)
