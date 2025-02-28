from flask import Flask, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate  # Importar Flask-Migrate
import os
from itsdangerous import URLSafeSerializer

# Inicializar extensiones
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

# Inicializar Flask-Migrate
migrate = Migrate()

def create_app():
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Templates'))
    app.config.from_object('config.Config')
    app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static')
    mail.init_app(app)

    # Inicializar la base de datos, el sistema de login y Flask-Migrate
    db.init_app(app)
    migrate.init_app(app, db)  # Inicializar Flask-Migrate
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    with app.app_context():
        # Registrar Blueprints
        from .routes import main_bp
        app.register_blueprint(main_bp)

        # Rutas adicionales
        @app.route('/manifest.json')
        def manifest():
            return send_from_directory('static', 'manifest.json')

        @app.route('/service-worker.js')
        def service_worker():
            return send_from_directory('static', 'service-worker.js')

        @app.route('/static/<path:filename>')
        def custom_static(filename):
            return send_from_directory(app.static_folder, filename)

        # Token generator para funcionalidad personalizada
        @app.context_processor
        def inject_generate_token():
            def generate_token(ticket_id):
                serializer = URLSafeSerializer(app.config['SECRET_KEY'])
                return serializer.dumps(ticket_id)
            return dict(generate_token=generate_token)

    return app

# Cargar el usuario para la sesión de Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from .models import Usuario  # Importar modelo de usuario para evitar problemas circulares
    return Usuario.query.get(int(user_id))