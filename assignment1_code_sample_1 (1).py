import os
import pymysql
import subprocess
import ssl
import urllib.request
from urllib.error import URLError
from dotenv import load_dotenv  # Securely loads environment variables
 
# Load environment variables securely
load_dotenv()
 
# Secure database configuration using environment variables
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'admin'),
    'password': os.getenv('DB_PASSWORD'),  # Removed hardcoded password
    'database': os.getenv('DB_NAME', 'secure_db')
}
 
def get_user_input():
    """Sanitize and validate user input to prevent injection attacks"""
    user_input = input('Enter your name: ').strip()
   
    # Validate input to allow only alphabets and spaces, with a max length of 50 characters
    if not user_input.replace(" ", "").isalpha() or len(user_input) > 50:
        print("Invalid input. Only letters and spaces (max 50 characters) are allowed.")
        return None
   
    return user_input
 
def send_email(to, subject, body):
    """
    Secure email sending function.
    Avoids command injection by using smtplib instead of subprocess.
    OWASP Category: A03:2021 - Injection
    """
    import smtplib
    from email.message import EmailMessage
 
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = os.getenv('EMAIL_SENDER', 'noreply@example.com')
        msg['To'] = to
 
        with smtplib.SMTP_SSL(os.getenv('SMTP_HOST', 'smtp.example.com'), 465) as server:
            server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
            server.send_message(msg)
 
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")
 
def get_data():
    """
    Fetch data from an API securely using HTTPS.
    OWASP Category: A08:2021 - Software and Data Integrity Failures
    """
    import requests  # Using requests for better error handling
 
    url = 'https://secure-api.com/get-data'  # Ensuring secure API access
 
    try:
        response = requests.get(url, timeout=5)  # Added timeout to prevent hanging requests
        response.raise_for_status()  # Raise an error for HTTP failures
        return response.json()  # Ensures response is valid JSON
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return None
 
def save_to_db(data):
    """
    Securely saves data to the database using parameterized queries to prevent SQL injection.
    OWASP Category: A03:2021 - Injection
    """
    import re  # Import regex for input validation
 
    if data is None or not isinstance(data, str) or not re.match(r"^[a-zA-Z0-9\s]+$", data):
        print("Invalid data provided. Only alphanumeric characters and spaces allowed.")
        return
 
    query = "INSERT INTO mytable (column1, column2) VALUES (%s, %s)"
   
    try:
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute(query, (data, 'Another Value'))  # Using parameterized query
        connection.commit()
        print("Data successfully saved to the database.")
    except pymysql.MySQLError as e:
        print(f"Database error: {e}")
    finally:
        cursor.close()
        connection.close()
 
if __name__ == '__main__':
    user_input = get_user_input()
    if user_input:
        data = get_data()
        save_to_db(data)
        send_email('admin@example.com', 'User Input', user_input)