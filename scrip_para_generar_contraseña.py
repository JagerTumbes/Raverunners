from werkzeug.security import generate_password_hash

# Generar un hash de contraseña
contraseña_plana = "admin123"
contraseña_cifrada = generate_password_hash(contraseña_plana, method='pbkdf2:sha256')
print(contraseña_cifrada)