import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Rutas a los archivos de certificado y clave privada
    cert_path = os.path.join(os.getcwd(), 'ssl', 'cert.pem')
    key_path = os.path.join(os.getcwd(), 'ssl', 'key.pem')

    # Verificar que los archivos de certificado existen
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError("Los archivos de certificado SSL no se encontraron. Asegúrate de que 'ssl/cert.pem' y 'ssl/key.pem' existan.")

    # Iniciar Flask con HTTPS
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        ssl_context=(cert_path, key_path)  # Habilitar HTTPS
    )