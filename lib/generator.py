import random
import re
import string
import secrets

lowercase = list(string.ascii_lowercase)  # Lowercase letters a-z
uppercase = list(string.ascii_uppercase)  # Uppercase letters A-Z
digits = list(string.digits)              # Digits 0-9
special_characters = list(string.punctuation)  # Special characters like !, @, #, etc.

def check_strength(password):
    alert = True
    score = 0
    feedback = {
        "length": False,
        "uppercase": False,
        "lowercase": False,
        "digits": False,
        "special_characters": False,
        "common_patterns": False
    }

    # Check length
    if len(password) >= 8:
        score += 1
        feedback["length"] = True

    if len(password) >= 12:
        score += 1

    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
        feedback["uppercase"] = True

    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
        feedback["lowercase"] = True

    # Check for digits
    if re.search(r'[0-9]', password):
        score += 1
        feedback["digits"] = True

    # Check for special characters
    if re.search(r'[\W_]', password):  # \W checks for non-word characters
        score += 1
        feedback["special_characters"] = True

    # Avoid common words or patterns
    common_patterns = ['password', '123456', 'qwerty']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 2  # Deduct points for weak patterns
        feedback["common_patterns"] = True

    # Password strength evaluation
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"
        alert = False

    # Final result
    return alert, strength, feedback

def gen_random_passwd(length, upper, digits, spl):
    password = ""
    
    alphabet = string.ascii_lowercase

    # Add uppercase letters if requested
    if upper:
        alphabet += string.ascii_uppercase

    # Add digits if requested
    if digits:
        alphabet += string.digits

    # Add punctuation if requested
    if spl:
        alphabet += '!@#$%^&*/?|;:=+<>'

    # Ensure at least one character type is selected
    if not alphabet:
        raise ValueError("No character types selected. Please choose at least one type.")

    # Generate the password
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password
