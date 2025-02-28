from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp


class LoginForm(FlaskForm):
    apodo = StringField('Apodo', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])

class CrearFuncionarioForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    apellido = StringField('Apellido', validators=[DataRequired()])
    apodo = StringField('Apodo', validators=[DataRequired()])
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    rut = StringField('RUT', validators=[DataRequired(), Length(min=9, max=9), Regexp('^\d{9}$', message='El RUT debe contener exactamente 9 dígitos numéricos.')])  # RUT de 9 dígitos


class RegisterRaverForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired(), Length(max=100)])
    apellido = StringField('Apellido', validators=[DataRequired(), Length(max=100)])
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email(), Length(max=120)])
    apodo = StringField('Apodo', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Contraseña', validators=[
        DataRequired(),
        Length(min=6),
        EqualTo('confirm_password', message='Las contraseñas deben coincidir.')
    ])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired()])
    rut = StringField('RUT', validators=[DataRequired(), Length(min=9, max=9), Regexp('^\d{9}$', message='El RUT debe contener exactamente 9 dígitos numéricos.')])  # RUT de 9 dígitos
    submit = SubmitField('Registrar')

class CambiarEstadoForm(FlaskForm):
    pass