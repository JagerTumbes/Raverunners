import os
class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:admin@localhost:3306/raverunners'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'tesisusm123'
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)),'static', 'images')
    STATIC_FOLDER = 'static'

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'servicios.integrales.lomas@gmail.com'
    MAIL_PASSWORD = 'qjth jkdy ewrr yhir'
    MAIL_DEFAULT_SENDER = ('Aplicacion tickets', 'servicios.integrales.lomas@gmail.com')
    