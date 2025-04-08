from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import sqlite3
import jwt
import datetime
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
SECRET_KEY = os.getenv("SECRET_KEY", "segredo")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ==== Pydantic Schemas ====

class UsuarioCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "usuario"

class UsuarioLogin(BaseModel):
    username: str
    password: str

class TarefaCreate(BaseModel):
    usuario_id: int
    tarefa: str
    status: str


# ==== Banco de dados ====

def create_table_usuarios():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'usuario')''')
    conn.commit()
    conn.close()

def create_table_tarefas():
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS tarefas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tarefa TEXT NOT NULL,
        status TEXT NOT NULL,
        usuario_id INTEGER NOT NULL,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id))''')
    conn.commit()
    conn.close()

create_table_usuarios()
create_table_tarefas()

# ==== JWT ====

def criar_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


# ==== Rotas ====

@app.post("/registro")
def registrar_usuario(usuario: UsuarioCreate):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO usuarios (username, password, role) VALUES (?, ?, ?)", 
                   (usuario.username, usuario.password, usuario.role))
    conn.commit()
    conn.close()
    return {"message": "Usuário registrado com sucesso"}

@app.post("/login")
def login(usuario: UsuarioLogin):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE username=?", (usuario.username,))
    user = cursor.fetchone()
    conn.close()
    if user and user[2] == usuario.password:  # Trocar pra hash depois
        token = criar_token(user[0], user[3])
        return {"token": token}
    raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")

@app.post("/criar-tarefa")
def criar_tarefa(tarefa: TarefaCreate, token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    conn = sqlite3.connect('tarefas.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tarefas (tarefa, status, usuario_id) VALUES (?, ?, ?)",
                   (tarefa.tarefa, tarefa.status, tarefa.usuario_id))
    conn.commit()
    conn.close()
    return {"message": "Tarefa criada com sucesso"}
