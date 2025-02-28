from flask_mail import Message
from app import mail

def enviar_correo_ticket(ticket):
    msg = Message(f"Nuevo Ticket #{ticket.id} creado",
                  recipients=["matias.maldonadoco@gmail.com "])
    msg.body = f"""
    Se ha creado un nuevo ticket.

    ID del ticket: {ticket.id}
    Problema: {ticket.problema}
    Descripción: {ticket.descripcion}
    Usuario: {ticket.usuario.username}
    Empresa: {ticket.empresa.nombre}
    Estado: {ticket.estado}
    Hora de creación: {ticket.hora_de_creacion}
    """

    mail.send(msg)