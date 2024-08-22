from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Inicializar la conexión a la base de datos
mysql = MySQL(app)

# Configurar la sesión
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

@app.route('/')
def pagina_login():
    return render_template('login.html')

 
@app.route('/register', methods=['GET', 'POST'])
def pagina_registro():
    if request.method == 'POST':
        variable_nombre_usuario = request.form['nombre_usuario_parabd']
        variable_contrasena = request.form['contrasena_usuario_parabd']
        variable_confirmar_contrasena = request.form['confirmar_contrasena_pagina']

        # Verificar si el nombre de usuario ya existe
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE nombre_usuario = %s", [variable_nombre_usuario])
        existing_user = cursor.fetchone()
        cursor.close()

        if existing_user:
            flash('El nombre de usuario ya está en uso. Intenta con otro.', 'danger')
            return redirect(url_for('pagina_registro'))

        # Validar que las contraseñas coincidan
        if variable_contrasena != variable_confirmar_contrasena:
            flash('Las contraseñas no coinciden. Intenta de nuevo.', 'danger')
            return redirect(url_for('pagina_registro'))

        # Hash de la contraseña
        contrasena_hashed = generate_password_hash(variable_contrasena)

        # Insertar usuario en la base de datos
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO usuarios (nombre_usuario, contrasena) VALUES (%s, %s)", 
                       (variable_nombre_usuario, contrasena_hashed))
        mysql.connection.commit()
        cursor.close()

        flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('pagina_login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nombre_usuario = request.form['nombre_usuario_parabd']
        contrasena = request.form['contrasena_usuario_parabd']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE nombre_usuario = %s", [nombre_usuario])
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user[2], contrasena):
            session['nombre_usuario'] = user[1]
            return redirect(url_for('dashboard'))

        flash('Nombre de usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'nombre_usuario' not in session:
        return redirect(url_for('pagina_login'))

    return render_template('dashboard.html', nombre_usuario=session['nombre_usuario'])

if __name__ == '__main__':
    app.run(debug=True)
