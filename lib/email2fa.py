import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

def check_otp(given_otp, otp) -> bool:
    if given_otp == otp:
        return True
    else:
        return False

# Function to generate a 2FA code
def generate_2fa_code():
    return random.randint(100000, 999999)  # Generates a 6-digit code

# Function to send email (2FA or alert)
def send_email(receiver_email, subject, body):
    sender_email = "hexavault012@gmail.com"
    sender_password = "pdwgmwfeqjoisjsb"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print(f"{subject} email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def send_2fa(user_email: str):
    generated_code = generate_2fa_code()  # Code valid for 10 minutes
    print(generated_code)
#    send_email(user_email, "Your HexaVault 2FA Code", 
#                f"Your 2FA code is: {generated_code}. It is valid for the next 10 minutes.")
    return generated_code
