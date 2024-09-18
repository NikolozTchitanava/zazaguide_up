from werkzeug.security import generate_password_hash

new_password_hash = generate_password_hash('#Adminirtupropka44', method='pbkdf2:sha256')
print(new_password_hash)
