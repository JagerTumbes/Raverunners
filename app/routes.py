from datetime import datetime, timezone
import os
from flask import Blueprint, jsonify, request, current_app, send_file
from flask import render_template, redirect, url_for, flash, render_template_string
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import ValidationError
from .models import Evento, Funcionario, LogInventario, ObjetoInventario, Raver, Usuario, DJ
from .forms import CambiarEstadoForm, CrearFuncionarioForm, LoginForm, RegisterRaverForm
from sqlalchemy.orm.attributes import flag_modified
from werkzeug.utils import secure_filename
import qrcode
from . import db
from pyzbar.pyzbar import decode
import logging
import io
import re

import numpy as np

from io import BytesIO

main_bp = Blueprint('main', __name__)

from flask import render_template, redirect, url_for, flash
from flask_login import current_user, login_required
from app import db
from app.models import Usuario
from app.forms import LoginForm
from app.routes import main_bp

# Configurar el logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def validate_rut(form, field):
    if not field.data.isdigit() or len(field.data) != 9:
        raise ValidationError('El RUT debe contener exactamente 9 dígitos numéricos.')
    
# Página de inicio, redirige a login por defecto
@main_bp.route('/')
def index():
    return redirect(url_for('main.login'))  # Redirigir a la página de login

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Buscar el usuario por el apodo
        usuario = Usuario.query.filter_by(apodo=form.apodo.data).first()

        if usuario and check_password_hash(usuario.password, form.password.data):
            # Si el apodo existe y la contraseña es correcta
            flash('¡Inicio de sesión exitoso!', 'success')

            # Iniciar sesión con el usuario encontrado
            login_user(usuario)

            # Redirigir según el tipo de usuario
            if usuario.tipo_usuario == 'admin':
                return redirect(url_for('main.inicio_admin'))  # Redirigir al inicio del admin
            elif usuario.tipo_usuario == 'raver':
                return redirect(url_for('main.inicio_raver'))  # Redirigir al inicio del raver
            elif usuario.tipo_usuario == 'funcionario':
                return redirect(url_for('main.inicio_funcionario'))  # Redirigir al inicio del funcionario
            elif usuario.tipo_usuario == 'dj':
                return redirect(url_for('main.inicio_dj'))  # Redirigir al inicio del DJ
            else:
                return redirect(url_for('main.index'))  # Si no es ninguno de los anteriores, redirigir a la página principal

        else:
            # Si el apodo o la contraseña no son correctos
            flash('Apodo o contraseña incorrectos. Inténtalo de nuevo.', 'danger')

    return render_template('login.html', form=form)

@main_bp.route('/logout')
def logout():
    logout_user()  # Cierra la sesión del usuario
    flash('Has cerrado sesión correctamente.', 'success')  # Mensaje de éxito
    return redirect(url_for('main.login'))  # Redirigir al login después de cerrar sesión

# Página de inicio para el administrador
@main_bp.route('/inicio_admin')
@login_required  # Solo usuarios logueados pueden acceder
def inicio_admin():
    # Verificar si el usuario es un admin
    if current_user.tipo_usuario != 'admin':
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('main.index'))  # Redirigir a la página principal si no es admin

    return render_template('inicio_admin.html')  # Renderizar la página de inicio del admin


@main_bp.route('/crear_funcionario', methods=['GET', 'POST'])
@login_required
def crear_funcionario():
    # Verificar si el usuario es un administrador
    if current_user.tipo_usuario != 'admin':
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('index'))

    form = CrearFuncionarioForm()

    if form.validate_on_submit():
        # Crear el nuevo usuario (Funcionario)
        nuevo_usuario = Usuario(
            nombre=form.nombre.data,
            apellido=form.apellido.data,
            apodo=form.apodo.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            tipo_usuario='funcionario',  # Establecer el tipo de usuario
            rut=form.rut.data  # Guardar el RUT ingresado
        )

        # Agregar el nuevo usuario a la base de datos
        db.session.add(nuevo_usuario)
        db.session.commit()

        # Crear el nuevo funcionario asociando el usuario creado
        nuevo_funcionario = Funcionario(id=nuevo_usuario.id)

        # Agregar el funcionario a la base de datos
        db.session.add(nuevo_funcionario)
        db.session.commit()

        flash(f'Funcionario {nuevo_usuario.nombre} creado exitosamente!', 'success')
        return redirect(url_for('main.index'))  # Redirigir a la página principal (o la que desees)

    return render_template('crear_funcionario.html', form=form)


@main_bp.route('/register/raver', methods=['GET', 'POST'])
def register_raver():
    form = RegisterRaverForm()
    
    if form.validate_on_submit():
        # Obtener los datos del formulario
        nombre = form.nombre.data
        apellido = form.apellido.data
        email = form.email.data
        apodo = form.apodo.data
        password = form.password.data
        rut = form.rut.data

        # Validar que el email, apodo o rut no existan previamente
        usuario_existente = Usuario.query.filter(
            (Usuario.email == email) | (Usuario.apodo == apodo) | (Usuario.rut == rut)
        ).first()
        if usuario_existente:
            flash('El correo electrónico, apodo o RUT ya están en uso.', 'danger')
            return redirect(url_for('main.register_raver'))

        # Crear el hash de la contraseña
        hashed_password = generate_password_hash(password)

        # Crear el nuevo usuario
        nuevo_usuario = Usuario(
            nombre=nombre,
            apellido=apellido,
            email=email,
            password=hashed_password,
            tipo_usuario='raver',
            apodo=apodo,
            is_active=False,
            rut=rut
        )

        db.session.add(nuevo_usuario)

        try:
            # Intentar guardar el usuario primero para obtener su id
            db.session.commit()

            # Ahora que tenemos el id del nuevo usuario, podemos crear el raver
            nuevo_raver = Raver(id=nuevo_usuario.id)
            db.session.add(nuevo_raver)

            # Commit para guardar tanto el raver como el usuario
            db.session.commit()

            flash('Raver registrado exitosamente. Pendiente de activación por el administrador.', 'success')
            return redirect(url_for('main.login'))

        except Exception as e:
            db.session.rollback()  # Deshacer los cambios si hay un error
            print(f"Error al registrar el usuario: {str(e)}")  # Registrar el error completo
            flash(f'Error al registrar el usuario: {str(e)}', 'danger')
            return redirect(url_for('main.register_raver'))

    else:
        print("Errores en el formulario:", form.errors)  # Depuración
        flash("Por favor, corrige los errores en el formulario.", "danger")

    return render_template('register_raver.html', form=form)



@main_bp.route('/admin/usuarios', methods=['GET'])
def admin_usuarios():
    usuarios = Usuario.query.all()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@main_bp.route('/admin/usuarios/toggle/<int:usuario_id>/<action>', methods=['GET'])
def toggle_usuario(usuario_id, action):
    usuario = Usuario.query.get_or_404(usuario_id)
    if action == 'activar':
        usuario.is_active = True  # Cambiar de 'active' a 'is_active'
    elif action == 'desactivar':
        usuario.is_active = False  # Cambiar de 'active' a 'is_active'
    db.session.commit()
    return redirect(url_for('main.admin_usuarios'))

@main_bp.route('/inicio/raver')
def inicio_raver():
    if current_user.tipo_usuario != 'raver':
        # Redirigir si el usuario no es de tipo raver
        return redirect(url_for('main.inicio_funcionario'))  # O alguna otra página predeterminada

    # Si el usuario es raver, renderizamos la página de inicio para ravers
    return render_template('inicio_raver.html')  # Asegúrate de tener este template en tu carpeta de templates


@main_bp.route('/inicio/funcionario')
def inicio_funcionario():
    if current_user.tipo_usuario != 'funcionario':
        # Redirigir si el usuario no es de tipo funcionario
        return redirect(url_for('main.inicio_raver'))  # O alguna otra página predeterminada

    # Si el usuario es funcionario, renderizamos la página de inicio para funcionarios
    return render_template('inicio_funcionario.html')  # Asegúrate de tener este template en tu carpeta de templates

from datetime import datetime, timezone

@main_bp.route('/crear_evento', methods=['GET', 'POST'])
@login_required
def crear_evento():
    # Verificar si el usuario es un administrador
    if current_user.tipo_usuario != 'admin':
        flash("No tienes permisos para acceder a esta página.", "danger")
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        # Obtener los datos del formulario
        nombre = request.form.get('nombre')
        lugar = request.form.get('lugar')
        fecha_str = request.form.get('fecha')  # Fecha en formato YYYY-MM-DD
        tipo = request.form.get('tipo')  # Tipo de evento
        estado = request.form.get('estado', 'preparacion')

        # Validar que todos los campos obligatorios estén presentes
        if not nombre or not lugar or not fecha_str or not tipo:
            flash("Todos los campos son obligatorios.", "danger")
            return render_template('crear_evento.html')

        # Validar que el tipo de evento sea uno de los valores permitidos
        tipos_permitidos = ['rave', 'after', 'limpieza', 'eventos_locales', 'exploraciones_urbanas']
        if tipo not in tipos_permitidos:
            flash("El tipo de evento seleccionado no es válido.", "danger")
            return render_template('crear_evento.html')

        try:
            # Convertir la fecha a un objeto datetime con zona horaria
            fecha_naive = datetime.strptime(fecha_str, '%Y-%m-%d')  # Fecha sin zona horaria
            fecha_aware = fecha_naive.replace(tzinfo=timezone.utc)  # Agregar zona horaria UTC

            # Crear nuevo evento
            nuevo_evento = Evento(
                nombre=nombre,
                lugar=lugar,
                fecha=fecha_aware.date(),  # Guardar solo la fecha (sin hora)
                tipo=tipo,  # Guardar el tipo de evento
                estado=estado,
                asistentes=[]
            )

            # Agregar el evento a la base de datos
            db.session.add(nuevo_evento)
            db.session.commit()

            flash("Evento creado exitosamente.", "success")
            return redirect(url_for('main.inicio_admin'))

        except Exception as e:
            db.session.rollback()  # Deshacer los cambios en caso de error
            flash(f"Error al crear el evento: {str(e)}", "danger")
            return render_template('crear_evento.html')

    return render_template('crear_evento.html')

# Ruta para ver todos los eventos
@main_bp.route('/ver_eventos')
@login_required
def ver_eventos():
    eventos = Evento.query.all()  # Obtener todos los eventos
    return render_template('ver_eventos.html', eventos=eventos)

# Ruta para ver detalles de un evento
@main_bp.route('/detalle_evento/<int:evento_id>', methods=['GET'])
@login_required
def detalle_evento(evento_id):
    evento = Evento.query.get_or_404(evento_id)
    form = CambiarEstadoForm()
    return render_template('detalle_evento.html', evento=evento, form=form)

@main_bp.route('/cambiar_estado_evento/<int:evento_id>', methods=['POST'])
@login_required
def cambiar_estado_evento(evento_id):
    form = CambiarEstadoForm()
    if not form.validate_on_submit():
        flash("Solicitud inválida.", "danger")
        return redirect(url_for('main.detalle_evento', evento_id=evento_id))

    evento = Evento.query.get_or_404(evento_id)
    # Calcular el siguiente estado
    if evento.estado == 'preparacion':
        siguiente_estado = 'ocurriendo'
    elif evento.estado == 'ocurriendo':
        siguiente_estado = 'finalizado'
    else:
        siguiente_estado = 'preparacion'

    # Actualizar el estado
    evento.estado = siguiente_estado
    db.session.commit()

    flash(f"El estado del evento '{evento.nombre}' se ha cambiado a '{evento.estado}'.", "success")

    # Pasar evento y siguiente_estado a la plantilla
    return render_template('detalle_evento.html', evento=evento, form=form, siguiente_estado=siguiente_estado)

from flask import send_file
from io import BytesIO
import qrcode

@main_bp.route('/generar_qr/<int:raver_id>')
@login_required
def generar_qr(raver_id):
    try:
        # Verificar si el usuario autenticado es el Raver correspondiente o un admin
        if current_user.tipo_usuario == 'raver' and current_user.id != raver_id:
            return jsonify({"error": "No tienes permisos para acceder a este código QR."}), 403

        if current_user.tipo_usuario not in ['raver', 'admin']:
            return jsonify({"error": "No tienes permisos para acceder a esta función."}), 403

        # Buscar al Raver por su ID
        raver = Raver.query.get_or_404(raver_id)

        # Generar el contenido del QR
        qr_data = f"raver:{raver.id}"

        # Crear el objeto QRCode
        qr_image = qrcode.make(qr_data)

        # Guardar el QR en un buffer en memoria
        buffer = BytesIO()
        qr_image.save(buffer, format="PNG")
        buffer.seek(0)

        # Enviar el QR como respuesta
        return send_file(buffer, mimetype="image/png", as_attachment=False)

    except Exception as e:
        return jsonify({"error": f"Error al generar el QR: {str(e)}"}), 500

@main_bp.route('/generar_qr_pagina/<int:raver_id>')
@login_required
def generar_qr_pagina(raver_id):
    # Verificar si el usuario autenticado es el Raver correspondiente o un admin
    if current_user.tipo_usuario == 'raver' and current_user.id != raver_id:
        flash("No tienes permisos para acceder a este código QR.", "danger")
        return redirect(url_for('main.index'))

    if current_user.tipo_usuario not in ['raver', 'admin']:
        flash("No tienes permisos para acceder a esta función.", "danger")
        return redirect(url_for('main.index'))

    # Renderizar la página con el botón para generar el QR
    return render_template('generar_qr.html', raver_id=raver_id)

@main_bp.route('/escanear_qr', methods=['GET', 'POST'])
@login_required
def escanear_qr():
    if current_user.tipo_usuario not in ['funcionario', 'admin']:
        flash("No tienes permisos para acceder a esta función.", "danger")
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        codigoQR = request.form.get('codigoQR')

        # Buscar al raver por ID
        raver = Raver.query.get(codigoQR)
        
        if not raver:
            flash("Raver no encontrado con ese ID.", "danger")
            return redirect(url_for('main.escanear_qr'))

        # Buscar el evento con estado "ocurriendo"
        evento = Evento.query.filter_by(estado="ocurriendo").first()

        if not evento:
            flash("No hay eventos 'ocurriendo' para añadir asistentes.", "danger")
            return redirect(url_for('main.escanear_qr'))

        # Añadir el raver a la lista de asistentes
        if raver not in evento.asistentes:
            evento.asistentes.append(f"{raver.nombre} {raver.apellido} ('{raver.apodo}')")
            db.session.commit()
            flash(f"{raver.nombre} {raver.apellido} ha sido añadido como asistente al evento '{evento.nombre}'.", "success")
        else:
            flash("Este raver ya está registrado como asistente.", "warning")

        return redirect(url_for('main.inicio_funcionario'))  # Redirigir al listado de eventos

    return render_template('scan_qr.html')



@main_bp.route('/procesar_qr', methods=['POST'])
@login_required
def procesar_qr():
    try:
        print("Procesar QR: inicio del procesamiento.")  # Log inicial

        # Obtener los datos enviados como JSON
        data = request.get_json()
        print("Datos recibidos:", data)  # Log de los datos recibidos

        if not data or 'codigoQR' not in data:
            print("Error: No se proporcionó el campo 'codigoQR'.")
            flash("No se proporcionó ningún código QR.", "danger")
            return jsonify({"message": "No se proporcionó ningún código QR."}), 400

        codigo_qr = data['codigoQR']
        print("Código QR recibido:", codigo_qr)  # Log del código QR

        # Extraer el número al final del texto del QR
        match = re.search(r'\d+$', codigo_qr)
        if not match:
            print("Error: El formato del código QR no es válido.")
            flash("El código QR no tiene un formato válido.", "danger")
            return jsonify({"message": "El código QR no tiene un formato válido."}), 400

        raver_id = int(match.group())
        print("ID del raver extraído:", raver_id)  # Log del ID extraído

        # Buscar al raver en la base de datos
        raver = Raver.query.get(raver_id)
        if not raver:
            print(f"Error: No se encontró un raver con ID {raver_id}.")
            flash("Raver no encontrado.", "danger")
            return jsonify({"message": "Raver no encontrado."}), 404

        # Obtener el usuario asociado al raver
        usuario = Usuario.query.get(raver.id)
        if not usuario:
            print(f"Error: No se encontró un usuario asociado al raver con ID {raver_id}.")
            flash("Usuario asociado al raver no encontrado.", "danger")
            return jsonify({"message": "Usuario asociado al raver no encontrado."}), 404

        # Buscar el evento en estado "ocurriendo"
        evento = Evento.query.filter_by(estado="ocurriendo").first()
        if not evento:
            print("Error: No hay eventos en estado 'ocurriendo'.")
            flash("No hay eventos en estado 'ocurriendo'.", "danger")
            return jsonify({"message": "No hay eventos en estado 'ocurriendo'."}), 404

        # Verificar si el usuario ya está en la lista de asistentes
        if any(asistente['id'] == usuario.id for asistente in evento.asistentes):
            print("Advertencia: Este raver ya está registrado como asistente.")
            flash("Este raver ya está registrado como asistente.", "warning")
            return jsonify({"message": "Este raver ya está registrado como asistente."}), 200

        # Añadir el nuevo asistente a la lista
        nuevo_asistente = {
            "id": usuario.id,
            "nombre": usuario.nombre,
            "apellido": usuario.apellido,
            "apodo": usuario.apodo
        }

        evento.asistentes.append(nuevo_asistente)

        # Notificar a SQLAlchemy que la columna "asistentes" ha sido modificada
        flag_modified(evento, "asistentes")

        # Guardar los cambios en la base de datos
        db.session.commit()

        print(f"{usuario.nombre} {usuario.apellido} ha sido añadido al evento.")
        flash(f"{usuario.nombre} {usuario.apellido} ha sido añadido como asistente.", "success")
        return jsonify({"message": f"{usuario.nombre} {usuario.apellido} ha sido añadido como asistente."}), 200

    except Exception as e:
        print(f"Error inesperado: {str(e)}")  # Log de la excepción
        flash(f"Ocurrió un error al procesar el QR: {str(e)}", "danger")
        return jsonify({"message": f"Error: {str(e)}"}), 500


@main_bp.route('/djs', methods=['GET'])
@login_required
def listar_djs():
    djs = DJ.query.all()
    return render_template('djs.html', djs=djs)

@main_bp.route('/crear_dj', methods=['GET', 'POST'])
@login_required
def crear_dj():
    if current_user.tipo_usuario != 'admin':
        flash("No tienes permisos para acceder a esta página.", "danger")
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        nombre_dj = request.form.get('nombre_dj')
        descripcion = request.form.get('descripcion')
        foto = request.files.get('foto')

        # Guardar la foto si se proporciona
        foto_path = None
        if foto:
            foto_filename = secure_filename(foto.filename)
            foto_subfolder = 'dj'  # Subcarpeta específica para DJs
            foto.save(os.path.join(current_app.config['UPLOAD_FOLDER'], foto_subfolder, foto_filename))
            foto_path = foto_filename  # Solo guardar el nombre del archivo

        # Crear un nuevo usuario de tipo DJ
        nuevo_usuario = Usuario(
            nombre=request.form.get('nombre'),
            apellido=request.form.get('apellido'),
            apodo=nombre_dj,
            email=request.form.get('email'),
            password=generate_password_hash(request.form.get('password')),
            tipo_usuario='dj',
            rut=request.form.get('rut'),
            is_active=True
        )
        db.session.add(nuevo_usuario)
        db.session.commit()

        # Crear el nuevo DJ asociado al usuario
        nuevo_dj = DJ(nombre_dj=nombre_dj, descripcion=descripcion, foto=foto_path, id=nuevo_usuario.id)
        db.session.add(nuevo_dj)
        db.session.commit()

        # Generar el archivo HTML personalizado para el DJ
        dj_html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Página de {nombre_dj}</title>
            <link rel="stylesheet" href="{{{{ url_for('static', filename='css/styles.css') }}}}">
        </head>
        <body>
            <h1>Bienvenido a la página de {nombre_dj}</h1>
            <p>Esta es la página personalizada de {nombre_dj}.</p>
            
                <img src="{{{{ url_for('static', filename='images/dj/{foto_path}') }}}}" alt="{nombre_dj}" style="max-width: 300px;">
            
            <!-- Puedes agregar más contenido aquí -->
        </body>
        </html>
        """

        # Guardar el archivo HTML en la carpeta templates/djs/
        dj_html_path = os.path.join('templates', 'djs', f'dj_{nuevo_usuario.id}.html')
        with open(dj_html_path, 'w', encoding='utf-8') as file:
            file.write(render_template_string(dj_html_content))

        flash("DJ creado exitosamente.", "success")
        return redirect(url_for('main.listar_djs'))

    return render_template('crear_dj.html')

@main_bp.route('/inicio/dj')
@login_required  # Solo usuarios logueados pueden acceder
def inicio_dj():
    # Verificar si el usuario es un DJ
    if current_user.tipo_usuario != 'dj':
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('main.index'))  # Redirigir a la página principal si no es DJ

    return render_template('inicio_dj.html')  # Renderizar la página de inicio del DJ

@main_bp.route('/dj/<int:dj_id>')
def pagina_personalizada_dj(dj_id):
    # Obtener el DJ por su ID
    dj = DJ.query.get_or_404(dj_id)
    
    # Construir el nombre del archivo HTML basado en el dj_id
    template_name = f'djs/dj_{dj.id}.html'
    
    # Renderizar la plantilla específica del DJ
    return render_template(template_name, dj=dj)
    
@main_bp.route('/api/eventos', methods=['GET'])
@login_required
def obtener_eventos():
    # Obtener eventos futuros
    eventos = Evento.query.filter(Evento.fecha >= datetime.now().date()).all()

    # Formatear los eventos como JSON
    eventos_json = [
        {
            "id": evento.id_evento,
            "nombre": evento.nombre,
            "lugar": evento.lugar,
            "fecha": evento.fecha.strftime("%Y-%m-%d"),
            "estado": evento.estado,
            "tipo": evento.tipo  # Añadir el tipo de evento
        }
        for evento in eventos
    ]

    return jsonify(eventos_json)

@main_bp.route('/calendario')
@login_required  # Solo usuarios logueados pueden acceder
def calendario():
    # Verificar si el usuario tiene permisos para ver el calendario
    if current_user.tipo_usuario not in ['admin', 'raver', 'funcionario', 'dj']:
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('main.index'))  # Redirigir a la página principal

    # Renderizar la página del calendario
    return render_template('calendario.html')

@main_bp.route('/dia/<int:year>/<int:month>/<int:day>')
@login_required
def ver_dia(year, month, day):
    # Convertir los parámetros en un objeto Date
    selected_date = datetime(year, month, day).date()

    # Obtener los eventos para ese día
    eventos_del_dia = Evento.query.filter(
        Evento.fecha == selected_date
    ).all()

    # Renderizar la página con los eventos del día
    return render_template('ver_dia.html', eventos=eventos_del_dia, fecha=selected_date)

@main_bp.route('/evento/<int:evento_id>/asociar_djs', methods=['GET', 'POST'])
@login_required
def asociar_djs_a_evento(evento_id):
    # Verificar si el usuario es un administrador
    if current_user.tipo_usuario != 'admin':
        flash("No tienes permisos para acceder a esta página.", "danger")
        return redirect(url_for('main.index'))

    evento = Evento.query.get_or_404(evento_id)
    djs_disponibles = DJ.query.all()

    if request.method == 'POST':
        # Obtener los IDs de los DJs seleccionados
        dj_ids = request.form.getlist('djs')

        # Limpiar los DJs actuales del evento
        evento.djs.clear()

        # Asociar los nuevos DJs al evento
        for dj_id in dj_ids:
            dj = DJ.query.get(dj_id)
            if dj:
                evento.djs.append(dj)

        db.session.commit()
        flash(f"DJs asociados al evento '{evento.nombre}' exitosamente.", "success")
        return redirect(url_for('main.ver_eventos'))  # Redirigir a la lista de eventos

    return render_template('asociar_djs.html', evento=evento, djs_disponibles=djs_disponibles)

@main_bp.route('/dj/eventos_asociados/<int:dj_id>', methods=['GET'])
def eventos_asociados_dj(dj_id):
    # Obtener el DJ por su ID
    dj = DJ.query.get_or_404(dj_id)

    # Obtener los eventos asociados al DJ
    eventos = [
        {
            "id": evento.id_evento,
            "title": evento.nombre,
            "start": evento.fecha.strftime('%Y-%m-%d'),
            "url": url_for('main.detalle_evento', evento_id=evento.id_evento, _external=True)
        }
        for evento in dj.eventos
    ]

    return jsonify(eventos)

@main_bp.route('/api/eventos-dj/<int:dj_id>', methods=['GET'])
def get_eventos_dj(dj_id):
    # Obtener el DJ por su ID
    dj = DJ.query.get_or_404(dj_id)
    
    # Construir la lista de eventos asociados al DJ
    eventos_asociados = []
    for evento in dj.eventos:
        eventos_asociados.append({
            'id': evento.id_evento,  # Usar id_evento en lugar de id
            'title': evento.nombre,
            'start': evento.fecha.strftime('%Y-%m-%d'),
            'end': None,  # Si no hay fecha de finalización
            'isAssociated': True  # Marcar como asociado
        })
    
    # Devolver los eventos en formato JSON
    return jsonify(eventos_asociados)

# Ruta para listar los objetos
@main_bp.route('/inventario')
def lista_objetos():
    # Obtener todos los objetos del inventario
    objetos = ObjetoInventario.query.filter_by(activo=True).all()
    return render_template('inventario.html', objetos=objetos)

# Ruta para mostrar el formulario de creación
@main_bp.route('/inventario/crear', methods=['GET'])
def crear_objeto():
    return render_template('crear_objeto.html')

@main_bp.route('/inventario/guardar', methods=['POST'])
@login_required  # Solo usuarios autenticados pueden acceder
def guardar_objeto():
    try:
        # Obtener los datos del formulario
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        cantidad = int(request.form['cantidad'])
        tipo = request.form['tipo']

        # Verificar si ya existe un objeto con el mismo nombre
        objeto_existente = ObjetoInventario.query.filter_by(nombre=nombre).first()
        if objeto_existente:
            return jsonify({'success': False, 'message': 'Ya existe un objeto con ese nombre.'})

        # Crear un nuevo objeto
        nuevo_objeto = ObjetoInventario(
            nombre=nombre,
            descripcion=descripcion,
            cantidad=cantidad,
            tipo=tipo
        )

        # Guardar en la base de datos
        db.session.add(nuevo_objeto)
        db.session.commit()

        # Obtener el nombre del usuario autenticado
        usuario_nombre = current_user.nombre if current_user.is_authenticated else "Usuario Anónimo"
        print(f"Usuario registrado en el log (Crear): {usuario_nombre}")  # Depuración

        # Registrar el log
        log = LogInventario(
            accion="Crear",
            objeto_id=nuevo_objeto.id,
            objeto_nombre=nuevo_objeto.nombre,
            cantidad_anterior=0,  # No había cantidad antes de crear el objeto
            cantidad_nueva=nuevo_objeto.cantidad,
            usuario=usuario_nombre,  # Nombre del usuario autenticado
            fecha=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        # Devolver una respuesta JSON indicando éxito
        return jsonify({'success': True, 'message': 'Objeto creado exitosamente.'})
    except Exception as e:
        # Capturar cualquier error y devolver un mensaje descriptivo
        db.session.rollback()  # Deshacer cambios en caso de error
        return jsonify({'success': False, 'message': f'Error al procesar la solicitud: {str(e)}'})

@main_bp.route('/inventario/detalle/<int:objeto_id>')
@login_required
def detalle_objeto(objeto_id):
    # Obtener el objeto por su ID
    objeto = ObjetoInventario.query.get_or_404(objeto_id)
    return render_template('detalle_objeto.html', objeto=objeto)

@main_bp.route('/inventario/eliminar/<int:objeto_id>', methods=['POST'])
@login_required
def eliminar_objeto(objeto_id):
    try:
        # Obtener el objeto por su ID
        objeto = ObjetoInventario.query.get_or_404(objeto_id)

        # Guardar la cantidad anterior antes de modificarla
        cantidad_anterior = objeto.cantidad

        # Marcar el objeto como inactivo y establecer la cantidad en 0
        objeto.activo = False
        objeto.cantidad = 0

        # Registrar el log de eliminación
        usuario_nombre = current_user.nombre if current_user.is_authenticated else "Usuario Anónimo"
        log = LogInventario(
            accion="Eliminar",
            objeto_id=objeto.id,
            objeto_nombre=objeto.nombre,
            cantidad_anterior=cantidad_anterior,  # Cantidad antes de la eliminación
            cantidad_nueva=0,  # La nueva cantidad es 0
            usuario=usuario_nombre,
            fecha=datetime.utcnow()
        )
        db.session.add(log)

        # Guardar los cambios en la base de datos
        db.session.commit()

        # Redirigir a la lista de objetos
        flash('Objeto desactivado exitosamente.', 'success')
        return redirect(url_for('main.lista_objetos'))
    except Exception as e:
        # Capturar cualquier error y devolver un mensaje descriptivo
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error al procesar la solicitud: {str(e)}'})
    
@main_bp.route('/inventario/modificar/<int:objeto_id>', methods=['POST'])
@login_required  # Solo usuarios autenticados pueden acceder
def modificar_cantidad(objeto_id):
    try:
        # Obtener el objeto por su ID
        objeto = ObjetoInventario.query.get_or_404(objeto_id)
        
        # Determinar la acción (agregar o quitar)
        accion = request.form['accion']
        cantidad_anterior = objeto.cantidad

        if accion == 'agregar':
            objeto.cantidad += 1
        elif accion == 'quitar':
            if objeto.cantidad > 0:
                objeto.cantidad -= 1
            else:
                return jsonify({'success': False, 'message': 'La cantidad no puede ser menor a 0.'})
        
        # Guardar el cambio en la base de datos
        db.session.commit()

        # Obtener el nombre del usuario autenticado
        usuario_nombre = current_user.nombre if current_user.is_authenticated else "Usuario Anónimo"

        # Registrar el log
        log = LogInventario(
            accion=accion.capitalize(),
            objeto_id=objeto.id,
            objeto_nombre=objeto.nombre,
            cantidad_anterior=cantidad_anterior,
            cantidad_nueva=objeto.cantidad,
            usuario=usuario_nombre,  # Usar el nombre del usuario autenticado
            fecha=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        # Devolver una respuesta JSON
        return jsonify({
            'success': True,
            'message': f'Se ha {accion}do 1 unidad al objeto "{objeto.nombre}".',
            'nueva_cantidad': objeto.cantidad
        })
    except Exception as e:
        # Capturar cualquier error y devolver un mensaje descriptivo
        db.session.rollback()  # Deshacer cambios en caso de error
        return jsonify({'success': False, 'message': f'Error al procesar la solicitud: {str(e)}'})

@main_bp.route('/inventario/agregar-multiples/<int:objeto_id>', methods=['POST'])
@login_required  # Solo usuarios autenticados pueden acceder
def agregar_multiples(objeto_id):
    try:
        # Obtener el objeto por su ID
        objeto = ObjetoInventario.query.get_or_404(objeto_id)

        # Obtener la cantidad ingresada por el usuario
        cantidad = int(request.form['cantidad'])
        cantidad_anterior = objeto.cantidad
        objeto.cantidad += cantidad

        # Guardar el cambio en la base de datos
        db.session.commit()

        # Obtener el nombre del usuario autenticado
        usuario_nombre = current_user.nombre if current_user.is_authenticated else "Usuario Anónimo"
        print(f"Usuario registrado en el log (Agregar múltiples): {usuario_nombre}")  # Depuración

        # Registrar el log
        log = LogInventario(
            accion="Agregar múltiples",
            objeto_id=objeto.id,
            objeto_nombre=objeto.nombre,
            cantidad_anterior=cantidad_anterior,
            cantidad_nueva=objeto.cantidad,
            usuario=usuario_nombre,  # Nombre del usuario autenticado
            fecha=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        # Devolver una respuesta JSON
        return jsonify({
            'success': True,
            'message': f'Se han agregado {cantidad} unidades al objeto "{objeto.nombre}".',
            'nueva_cantidad': objeto.cantidad
        })
    except Exception as e:
        # Capturar cualquier error y devolver un mensaje descriptivo
        db.session.rollback()  # Deshacer cambios en caso de error
        return jsonify({'success': False, 'message': f'Error al procesar la solicitud: {str(e)}'})

@main_bp.route('/inventario/logs')
def lista_logs():
    # Obtener todos los logs ordenados por fecha descendente (los más recientes primero)
    logs = LogInventario.query.order_by(LogInventario.fecha.desc()).all()
    return render_template('lista_logs.html', logs=logs)