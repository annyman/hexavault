import bcrypt

def hash_passwd(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def check_passwd(password, hashed_password):
    # Check if the password matches the hashed password
    return bcrypt.checkpw(password.encode(), hashed_password)
