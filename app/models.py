import os
from flask import current_app
from . import db
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import qrcode
from io import BytesIO
from base64 import b64encode
from flask_login import UserMixin  # Importar UserMixin

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    tipo_usuario = db.Column(db.String(50), nullable=False)  # admin, funcionario, raver
    apodo = db.Column(db.String(100), unique=True, nullable=True)  # Apodo para login
    is_active = db.Column(db.Boolean, default=False)  # Valor predeterminado en False (inactivo)
    rut = db.Column(db.String(9), unique=True, nullable=False)  # RUT como número de 9 caracteres

    # Relaciones con tablas específicas
    admin = db.relationship('Admin', backref='usuario', uselist=False)
    funcionario = db.relationship('Funcionario', backref='usuario', uselist=False)
    raver = db.relationship('Raver', backref='usuario', uselist=False)

    def __repr__(self):
        return f"<Usuario {self.nombre} ({self.tipo_usuario})>"

    # Método para indicar si el usuario está activo
    def is_user_active(self):
        return self.is_active


class Admin(db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), primary_key=True)
    nivel_acceso = db.Column(db.String(50), default='superadmin')

    def __repr__(self):
        return f"<Admin {self.usuario.nombre}>"


class Funcionario(db.Model):
    __tablename__ = 'funcionarios'

    id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), primary_key=True)

    def __repr__(self):
        return f"<Funcionario {self.usuario.nombre}>"


class Raver(db.Model):
    __tablename__ = 'ravers'

    id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), primary_key=True, autoincrement=False)  # No usar autoincremento aquí

    def __repr__(self):
        return f"<Raver ID {self.id}>"

# Tabla intermedia para la relación muchos a muchos entre Evento y DJ
evento_dj = db.Table(
    'evento_dj',
    db.Column('id_evento', db.Integer, db.ForeignKey('eventos.id_evento'), primary_key=True),
    db.Column('id_dj', db.Integer, db.ForeignKey('djs.id'), primary_key=True)
)

class Evento(db.Model):
    __tablename__ = 'eventos'

    id_evento = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombre = db.Column(db.String(100), nullable=False)
    lugar = db.Column(db.String(100), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    tipo = db.Column(db.String(50), nullable=False)  # Nuevo campo para el tipo de evento
    asistentes = db.Column(db.JSON, nullable=True)  # Sin valor por defecto en la BD
    estado = db.Column(db.String(20), nullable=False, default='preparacion')

    # Relación muchos a muchos con DJs
    djs = db.relationship('DJ', secondary=evento_dj, back_populates='eventos')

    def __init__(self, nombre, lugar, fecha, tipo, estado='preparacion', asistentes=None):
        self.nombre = nombre
        self.lugar = lugar
        self.fecha = fecha
        self.tipo = tipo  # Inicializar el tipo de evento
        self.estado = estado
        self.asistentes = asistentes if asistentes is not None else []

class DJ(db.Model):
    __tablename__ = 'djs'

    id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), primary_key=True)
    nombre_dj = db.Column(db.String(80), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    foto = db.Column(db.String(255), nullable=True)

    # Relación muchos a muchos con Eventos
    eventos = db.relationship('Evento', secondary=evento_dj, back_populates='djs')

    def __repr__(self):
        return f"<DJ {self.nombre_dj}>"