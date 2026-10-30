import pickle
def load_data(data):
    return pickle.loads(data)  # insecure deserialization
import subprocess

# Command injection (Semgrep will catch this)
def run_user_input(cmd):
    subprocess.call(cmd, shell=True)

# Hardcoded password (Semgrep will catch this)
DB_PASSWORD = "super_secret_password_123"