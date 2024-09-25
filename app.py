from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FloatField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# Função de criação do aplicativo Flask
def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'  # URL do banco de dados
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Desabilitar notificações de alterações no SQLAlchemy
    app.config['SECRET_KEY'] = 'secret_key'  # Chave secreta para formulários e sessões
    db.init_app(app)  # Inicializar o banco de dados com o aplicativo

    # Configuração do LoginManager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'  # Página de login para usuários não autenticados

    # Função para carregar o usuário pelo ID (necessário para o Flask-Login)
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Registrando as rotas do aplicativo
    register_routes(app)

    # Criar o banco de dados antes de executar o app
    with app.app_context():
        db.create_all()

    return app

# Instância do banco de dados
db = SQLAlchemy()

# Modelo de Usuário (User)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    user_type = db.Column(db.String(50), nullable=False)  # Tipo de usuário: 'Doador' ou 'ONG'
    estabelecimento = db.Column(db.String(150))  # Nome do estabelecimento (opcional)
    endereco = db.Column(db.String(250))  # Endereço do estabelecimento
    telefone = db.Column(db.String(20))  # Telefone de contato

# Modelo de Alimento (Alimento)
class Alimento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    quantidade = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="Available")  # Status inicial como "Available"
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Relacionamento com User

    # Relacionamento com o doador
    doador = db.relationship('User', backref=db.backref('alimentos', lazy=True))

# Modelo de Formulário de Registro
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    user_type = SelectField('Account Type', choices=[('Doador', 'Donor'), ('ONG', 'ONG')], validators=[DataRequired()])
    estabelecimento = StringField('Establishment Name')  # Campo para nome do estabelecimento (opcional)
    endereco = StringField('Address', validators=[Length(min=10, max=250)])  # Campo para endereço
    telefone = StringField('Phone', validators=[Length(min=10, max=20)])  # Campo para telefone
    submit = SubmitField('Register')

    # Validação para garantir que o nome de usuário seja único
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose another one.')

# Modelo de Formulário de Login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Modelo de Formulário para Inserção de Alimentos
class AlimentoForm(FlaskForm):
    nome = StringField('Food Name', validators=[DataRequired()])
    quantidade = FloatField('Quantity (kg)', validators=[DataRequired()])
    submit = SubmitField('Add Food')

# Função para registrar as rotas
def register_routes(app):
    # Rota de Registro
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegistrationForm()  # Criação do formulário de registro
        if form.validate_on_submit():  # Verifica se o formulário é válido ao ser enviado
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')  # Gera o hash da senha
            new_user = User(
                username=form.username.data, 
                password=hashed_password, 
                user_type=form.user_type.data,
                estabelecimento=form.estabelecimento.data,  # Nome do estabelecimento
                endereco=form.endereco.data,  # Endereço
                telefone=form.telefone.data  # Telefone
            )
            db.session.add(new_user)  # Adiciona o novo usuário ao banco de dados
            db.session.commit()  # Confirma as mudanças no banco de dados
            flash('Account created successfully! You can now login.', 'success')  # Exibe mensagem de sucesso
            return redirect(url_for('login'))  # Redireciona para a página de login
        return render_template('register.html', form=form)  # Renderiza o template de registro com o formulário

    # Rota de Login
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()  # Criação do formulário de login
        if form.validate_on_submit():  # Verifica se o formulário é válido ao ser enviado
            user = User.query.filter_by(username=form.username.data).first()  # Busca o usuário pelo nome
            if user and check_password_hash(user.password, form.password.data):  # Verifica a senha
                login_user(user)  # Faz login do usuário
                if user.user_type == 'Doador':
                    return redirect(url_for('doador_dashboard'))  # Redireciona para o painel do doador
                elif user.user_type == 'ONG':
                    return redirect(url_for('ong_dashboard'))  # Redireciona para o painel da ONG
            else:
                flash('Invalid username or password. Please try again.', 'danger')  # Exibe mensagem de erro
        return render_template('login.html', form=form)  # Renderiza o template de login com o formulário

    # Rota do Painel do Doador
    @app.route('/doador_dashboard', methods=['GET', 'POST'])
    @login_required
    def doador_dashboard():
        if current_user.user_type != 'Doador':  # Verifica se o usuário é do tipo 'Doador'
            return redirect(url_for('login'))  # Redireciona para o login se não for doador
        
        # Formulário para adicionar novos alimentos
        form = AlimentoForm()

        # Se o formulário foi enviado e é válido, adiciona o novo alimento
        if form.validate_on_submit():
            novo_alimento = Alimento(
                nome=form.nome.data, 
                quantidade=form.quantidade.data,
                user_id=current_user.id  # Associa o alimento ao usuário logado
            )
            db.session.add(novo_alimento)
            db.session.commit()
            flash('Food added successfully!', 'success')
            return redirect(url_for('doador_dashboard'))

        # Obtém os alimentos doados pelo usuário logado
        alimentos = Alimento.query.filter_by(user_id=current_user.id).all()
        # Passa o nome do estabelecimento para o template
        estabelecimento = current_user.estabelecimento if current_user.estabelecimento else "Donor"
        return render_template('doador_dashboard.html', alimentos=alimentos, form=form, estabelecimento=estabelecimento)

    # Rota do Painel da ONG
    @app.route('/ong_dashboard')
    @login_required
    def ong_dashboard():
        if current_user.user_type != 'ONG':  # Verifica se o usuário é do tipo 'ONG'
            return redirect(url_for('login'))  # Redireciona para o login se não for ONG

        # Consulta para obter alimentos com informações dos doadores
        alimentos_disponiveis = Alimento.query.join(User).filter(Alimento.status == "Available").all()
        # Passa o nome do estabelecimento da ONG para o template
        nome_ong = current_user.estabelecimento if current_user.estabelecimento else "NGO"
        return render_template('ong_dashboard.html', alimentos=alimentos_disponiveis, nome_ong=nome_ong)

    # Rota Principal (Redireciona para login ou dashboards)
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if current_user.user_type == 'Doador':
                return redirect(url_for('doador_dashboard'))
            elif current_user.user_type == 'ONG':
                return redirect(url_for('ong_dashboard'))
        return redirect(url_for('login'))

    # Rota para atualizar o status do alimento para "Available" ou "Donated"
    @app.route('/update_status/<int:alimento_id>/<string:new_status>', methods=['POST'])
    @login_required
    def atualizar_status(alimento_id, new_status):
        # Verifica se o usuário é um doador
        if current_user.user_type != 'Doador':
            return redirect(url_for('login'))
        
        # Busca o alimento pelo ID
        alimento = Alimento.query.get_or_404(alimento_id)
        
        # Verifica se o alimento pertence ao usuário logado
        if alimento.user_id != current_user.id:
            flash('You do not have permission to update this food.', 'danger')
            return redirect(url_for('doador_dashboard'))
        
        # Atualiza o status do alimento
        alimento.status = new_status
        db.session.commit()
        flash(f'Status updated to "{new_status}".', 'success')
        return redirect(url_for('doador_dashboard'))

    # Rota de Logout (necessária para sair do sistema)
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()  # Faz logout do usuário atual
        flash('You have been logged out.', 'success')  # Mensagem de confirmação
        return redirect(url_for('login'))  # Redireciona para a página de login

# Executar o aplicativo Flask
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
