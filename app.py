from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recoll3d.db'  # banco de dados local
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Para proteger sessões

# Inicializa o SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Nome da rota de login

# Inicializa o LoginManager
login_manager.login_message = "Por favor, faça login para acessar essa página."
login_manager.login_message_category = "info"

# Modelo de usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)


    def set_password(self, password):
        """Hasheia a senha e a salva"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha inserida corresponde ao hash armazenado"""
        return check_password_hash(self.password, password)

@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return user
    return None

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Se o usuário já está autenticado, redirecione para a dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Se o método é POST, tentamos realizar o login
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        
        # Busca o usuário pelo nome de usuário
        user = User.query.filter_by(user=user).first()

        # Verifica se o usuário existe e se a senha está correta
        if user and check_password_hash(user.password, password):  # Idealmente usando senha com hash
            login_user(user)
            flash('Login bem-sucedido!', 'success')

            # Redireciona para a página pretendida ou dashboard
            next_page = request.args.get('next')  # Obtém a próxima página se o login foi exigido
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Nome de usuário ou senha incorretos.', 'danger')

    return render_template('login.html')
# Rota para dashboard (requer login)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user.user if current_user.is_authenticated else None)

# Rota de registro de usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['password']
        email = request.form['email']

        # Cria um novo usuário e hashea a senha
        new_user = User(user=user, email=email)
        new_user.set_password(password)  # Hashear a senha antes de salvar
        db.session.add(new_user)
        db.session.commit()

        new_user = User(user=user)

        flash('Registro realizado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Rota principal para renderizar o template
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login_page')
def login_page():
    return render_template('dashboard/auth-signin.html')

if __name__ == '__main__':
    app.run(debug=True)
