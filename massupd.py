from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import paramiko
import getpass
import yaml
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Load configuration files
with open("conf.yaml", "r") as file:
    conf = yaml.safe_load(file)

with open("managers.yaml", "r") as file:
    managers = yaml.safe_load(file)

filters = {}
encrypted_data_file = conf["conFile"]

log_directory = 'logs'
backup_directory = 'backups'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)
if not os.path.exists(backup_directory):
    os.makedirs(backup_directory)

# Helper functions
def derive_key(passphrase, salt=conf["salt"].encode(), iterations=100000):
    passphrase_bytes = passphrase.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    derived_key = kdf.derive(passphrase_bytes)
    return base64.urlsafe_b64encode(derived_key).decode('utf-8')

def encrypt_credentials(credentials, key):
    cipher_suite = Fernet(key)
    encrypted_credentials = cipher_suite.encrypt(json.dumps(credentials).encode())
    return base64.b64encode(encrypted_credentials).decode('utf-8')

def decrypt_credentials(encrypted_credentials, key):
    try:
        cipher_suite = Fernet(key)
        encrypted_credentials_bytes = base64.b64decode(encrypted_credentials)
        decrypted_credentials = cipher_suite.decrypt(encrypted_credentials_bytes)
        decrypted_credentials_str = decrypted_credentials.decode('utf-8')
        return json.loads(decrypted_credentials_str.replace("'", "\""))
    except:
        return None

def log(msg, to_console=False):
    if to_console:
        print(msg)
    log_filename = f'massupd-{datetime.now().strftime("%d-%m-%Y-%H-%M-%S")}.log'
    log_filepath = os.path.join(log_directory, log_filename)
    with open(log_filepath, 'a') as file:
        file.write(f'{datetime.now().strftime("[%d.%m.%Y %H:%M:%S]")} - {msg}\n')

def sanitize_output(output, password):
    sanitized_output = output.replace(password, '***')
    lines = [line.strip() for line in sanitized_output.splitlines() if line.strip()]
    return "\n".join(lines)

def log_output(ip, output, error, password):
    sanitized_output = sanitize_output(output, password)
    sanitized_error = sanitize_output(error, password)
    log_filename = f'massupd-{datetime.now().strftime("%d-%m-%Y-%H-%M-%S")}.log'
    log_filepath = os.path.join(log_directory, log_filename)
    with open(log_filepath, 'a') as file:
        file.write(f'{datetime.now().strftime("[%d.%m.%Y %H:%M:%S]")} - Output from {ip}:\n{sanitized_output}\n')
        if sanitized_error:
            file.write(f'{datetime.now().strftime("[%d.%m.%Y %H:%M:%S]")} - Errors from {ip}:\n{sanitized_error}\n')

@app.route('/')
def index():
    key = derive_key('yourpassword')  # Replace with your method of getting the key
    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    decrypted_connections = [decrypt_credentials(data, key) for data in encrypted_data]
    return render_template('index.html', connections=decrypted_connections)

@app.route('/connections', methods=['GET', 'POST'])
def manage_connections():
    key = derive_key('yourpassword')  # Replace with your method of getting the key
    if request.method == 'POST':
        action = request.form['action']
        if action == 'add':
            name = request.form['name']
            user = request.form['user']
            ip = request.form['ip']
            port = int(request.form['port'])
            password = request.form['password']
            password_sudo = request.form['password_sudo']
            manager = request.form['manager']
            
            new_connection = {
                "name": name,
                "user": user,
                "ip": ip,
                "port": port,
                "password": password,
                "passwordSudo": password_sudo,
                "manager": manager,
            }
            encrypted_connection = encrypt_credentials(new_connection, key)
            
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
            except FileNotFoundError:
                encrypted_data = []

            encrypted_data.append(encrypted_connection)
            with open(encrypted_data_file, "w") as file:
                json.dump(encrypted_data, file)
            
            flash("Connection added successfully!")
        elif action == 'remove':
            ip_to_remove = request.form['ip']
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
            except FileNotFoundError:
                encrypted_data = []

            encrypted_data = [data for data in encrypted_data if decrypt_credentials(data, key)['ip'] != ip_to_remove]
            with open(encrypted_data_file, "w") as file:
                json.dump(encrypted_data, file)
            
            flash("Connection removed successfully!")
        return redirect(url_for('manage_connections'))

    return render_template('connections.html', managers=managers.keys())

@app.route('/edit/<ip>', methods=['GET', 'POST'])
def edit_connection(ip):
    key = derive_key('yourpassword')  # Replace with your method of getting the key
    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    connection = next((decrypt_credentials(data, key) for data in encrypted_data if decrypt_credentials(data, key)['ip'] == ip), None)
    
    if request.method == 'POST':
        name = request.form['name']
        user = request.form['user']
        ip = request.form['ip']
        port = int(request.form['port'])
        password = request.form['password']
        password_sudo = request.form['password_sudo']
        manager = request.form['manager']
        
        updated_connection = {
            "name": name,
            "user": user,
            "ip": ip,
            "port": port,
            "password": password if password else connection['password'],
            "passwordSudo": password_sudo,
            "manager": manager,
        }
        encrypted_connection = encrypt_credentials(updated_connection, key)
        
        index = encrypted_data.index(next(data for data in encrypted_data if decrypt_credentials(data, key)['ip'] == ip))
        encrypted_data[index] = encrypted_connection
        
        with open(encrypted_data_file, "w") as file:
            json.dump(encrypted_data, file)
        
        flash("Connection updated successfully!")
        return redirect(url_for('index'))

    return render_template('edit_connection.html', connection=connection, managers=managers.keys())

@app.route('/backup', methods=['GET', 'POST'])
def backup():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'make':
            try:
                with open(encrypted_data_file, "r") as file:
                    encrypted_data = json.load(file)
                backup_filename = f'backup-{datetime.now().strftime("%d-%m-%Y-%H-%M-%S")}.json'
                backup_filepath = os.path.join(backup_directory, backup_filename)
                with open(backup_filepath, 'w') as backup_file:
                    json.dump(encrypted_data, backup_file)
                flash("Backup created successfully!")
            except Exception as e:
                flash(f"Failed to create backup: {e}")
        elif action == 'restore':
            backup_file = request.form['backup_file']
            backup_filepath = os.path.join(backup_directory, backup_file)
            try:
                with open(backup_filepath, "r") as file:
                    backup_data = json.load(file)
                with open(encrypted_data_file, "w") as file:
                    json.dump(backup_data, file)
                flash("Backup restored successfully!")
            except Exception as e:
                flash(f"Failed to restore backup: {e}")
        elif action == 'upload':
            if 'backup_file' not in request.files:
                flash("No file part")
                return redirect(request.url)
            file = request.files['backup_file']
            if file.filename == '':
                flash("No selected file")
                return redirect(request.url)
            if file:
                filename = file.filename
                file.save(os.path.join(backup_directory, filename))
                flash("Backup uploaded successfully!")
        return redirect(url_for('backup'))

    backups = os.listdir(backup_directory)
    backups.sort(reverse=True)
    return render_template('backup.html', backups=backups)

@app.route('/log', methods=['GET'])
def log_view():
    log_files = os.listdir(log_directory)
    log_files.sort(reverse=True)  # Show the latest log files first
    return render_template('log.html', log_files=log_files)

@app.route('/log/<filename>', methods=['GET'])
def view_log(filename):
    if filename not in os.listdir(log_directory):
        flash("Log file not found!")
        return redirect(url_for('log_view'))

    with open(os.path.join(log_directory, filename), 'r') as file:
        log_content = file.read()
    
    return render_template('view_log.html', log_content=log_content, filename=filename)

@app.route('/update/<ip>', methods=['POST'])
def update(ip):
    key = derive_key('yourpassword')  # Replace with your method of getting the key
    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    connection = next((decrypt_credentials(data, key) for data in encrypted_data if decrypt_credentials(data, key)['ip'] == ip), None)
    if connection:
        output, error = update_system(connection)
        log_output(ip, output, error, connection["password"])
        flash(f"Update started on {ip}.")
    else:
        flash(f"No connection found for IP {ip}.")

    return redirect(url_for('index'))

@app.route('/update_all', methods=['POST'])
def update_all():
    key = derive_key('yourpassword')  # Replace with your method of getting the key
    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    connections = [decrypt_credentials(data, key) for data in encrypted_data]

    for connection in connections:
        if connection:
            output, error = update_system(connection)
            log_output(connection['ip'], output, error, connection["password"])
            flash(f"Update started on {connection['ip']}.")

    return redirect(url_for('index'))

@app.route('/test_all', methods=['POST'])
def test_all():
    key = derive_key('yourpassword')  # Replace with your method of getting the key
    try:
        with open(encrypted_data_file, "r") as file:
            encrypted_data = json.load(file)
    except FileNotFoundError:
        encrypted_data = []

    connections = [decrypt_credentials(data, key) for data in encrypted_data]

    for connection in connections:
        if connection:
            test_connection(connection)
            flash(f"Test started on {connection['ip']}.")

    return redirect(url_for('index'))

def test_connection(connection):
    user = connection["user"]
    ip = connection["ip"]
    port = connection["port"]
    password = connection["password"]
    sudo_password = connection["passwordSudo"]

    output = ""
    error = ""

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=password, port=port)

        command = conf["testCommand"]
        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)

        if sudo_password not in ['y', 'yes']:
            stdin.write(password + '\n')
            stdin.flush()

        stdout.channel.recv_exit_status()

        output = stdout.read().decode()
        error = stderr.read().decode()

        if stdout.channel.recv_exit_status() != 0:
            log(f'Error testing {ip}: (Exit code {stdout.channel.recv_exit_status()})', True)
        else:
            log(f"Test on {ip} completed successfully.", True)

    except Exception as e:
        error = str(e)
        log(f"Error testing {ip}, {e}", True)
    finally:
        ssh.close()

    log_output(ip, output, error, password)

def update_system(connection):
    user = connection["user"]
    ip = connection["ip"]
    port = connection["port"]
    password = connection["password"]
    package_manager = connection["manager"]
    sudo_password = connection["passwordSudo"]

    output = ""
    error = ""

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=password, port=port)

        command = managers[package_manager]
        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)

        if sudo_password not in ['y', 'yes']:
            stdin.write(password + '\n')
            stdin.flush()

        stdout.channel.recv_exit_status()

        output = stdout.read().decode()
        error = stderr.read().decode()

        if stdout.channel.recv_exit_status() != 0:
            log(f'Error updating {ip}: (Exit code {stdout.channel.recv_exit_status()})', True)
        else:
            log(f"Update on {ip} using {package_manager} completed.", True)

    except Exception as e:
        error = str(e)
        log(f"Error updating {ip}, {e}", True)
    finally:
        ssh.close()

    return output, error

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
