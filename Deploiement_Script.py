import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import MySQLdb
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import re

# Chemins des fichiers de configuration
CONFIG_FILE = "db_config.json"
RECIPIENTS_FILE = "recipients.json"
EMAIL_MESSAGE_FILE = "email_message.txt"
CREDENTIALS_FILE = "credentials.json"

# Charger les configurations des serveurs depuis le fichier JSON
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return json.load(file)
    return {}

# Sauvegarder les configurations des serveurs dans le fichier JSON
def save_config(config):
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)

# Charger la liste des destinataires depuis le fichier JSON
def load_recipients():
    if os.path.exists(RECIPIENTS_FILE):
        with open(RECIPIENTS_FILE, 'r') as file:
            return json.load(file)
    return {"recipients": []}

 # Vérifier un mot de passe avec un hachage salé
def verify_password(stored_hash, password_to_check):
    try:
        # Extraire le sel et le hachage stocké
        salt, stored_sha256 = stored_hash.split('$')
        # Recalculer le hachage avec le sel et le mot de passe saisi
        salted_password = salt + password_to_check
        new_sha256_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        # Comparer les hachages
        return new_sha256_hash == stored_sha256
    except Exception:
        return False

# Lire le contenu du fichier de message e-mail
def load_email_message():
    if os.path.exists(EMAIL_MESSAGE_FILE):
        with open(EMAIL_MESSAGE_FILE, 'r', encoding='utf-8') as file:
            return file.read()
    return "Le script a été exécuté avec succès sur tous les serveurs."

# Charger les identifiants d'authentification depuis le fichier JSON
def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as file:
            return json.load(file)
    return {"username": "", "password_hash": ""}

# Hacher un mot de passe
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def remove_comments(sql):
    # Supprimer les commentaires de type '--'
    sql = re.sub(r'--.*', '', sql)
    # Supprimer les commentaires de type '/* ... */'
    sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
    # Supprimer les lignes vides ou espaces inutiles
    sql = '\n'.join(line.strip() for line in sql.splitlines() if line.strip())
    return sql

# Vérifier les identifiants
def authenticate(username, password):
    credentials = load_credentials()
    stored_username = credentials.get("username", "")
    stored_password_hash = credentials.get("password_hash", "")

    if username == stored_username and verify_password(stored_password_hash, password):
        return True
    return False

# Interface graphique principale
class SQLExecutorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Utilitaire d'exécution SQL Multi-Serveur")
        self.root.resizable(False, False)  # Bloquer le redimensionnement de la fenêtre

        # Charger les configurations des serveurs
        self.config = load_config()

        # Variables pour les champs de saisie
        self.server_name_var = tk.StringVar()
        self.host_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.database_var = tk.StringVar()
        self.ssl_ca_var = tk.StringVar(value="certif\\DEV-14.pem")  # Chemin par défaut du certificat SSL

        # Dictionnaire pour suivre l'état des cases à cocher
        self.check_vars = {}

        # Création des widgets
        self.create_widgets()

    def create_widgets(self):
        # Frame pour la gestion des serveurs
        server_frame = ttk.LabelFrame(self.root, text="Gestion des Serveurs")
        server_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        ttk.Label(server_frame, text="Nom du Serveur:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(server_frame, textvariable=self.server_name_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(server_frame, text="Host:").grid(row=1, column=0, padx=5, pady=5)
        ttk.Entry(server_frame, textvariable=self.host_var).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(server_frame, text="Utilisateur:").grid(row=2, column=0, padx=5, pady=5)
        ttk.Entry(server_frame, textvariable=self.user_var).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(server_frame, text="Mot de passe:").grid(row=3, column=0, padx=5, pady=5)
        ttk.Entry(server_frame, textvariable=self.password_var, show="*").grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(server_frame, text="Base de données:").grid(row=4, column=0, padx=5, pady=5)
        ttk.Entry(server_frame, textvariable=self.database_var).grid(row=4, column=1, padx=5, pady=5)

        ttk.Label(server_frame, text="Certificat SSL (chemin):").grid(row=5, column=0, padx=5, pady=5)
        ttk.Entry(server_frame, textvariable=self.ssl_ca_var, width=40).grid(row=5, column=1, padx=5, pady=5)
        ttk.Button(server_frame, text="Parcourir", command=self.browse_ssl_cert).grid(row=5, column=2, padx=5, pady=5)

        ttk.Button(server_frame, text="Ajouter/Modifier Serveur", command=self.add_or_update_server).grid(row=6, column=0, columnspan=3, pady=10)

        # Bouton pour supprimer un serveur
        ttk.Button(server_frame, text="Supprimer Serveur", command=self.delete_server).grid(row=7, column=0, columnspan=3, pady=5)

        # Frame pour l'exécution des scripts
        script_frame = ttk.LabelFrame(self.root, text="Exécution de Scripts SQL")
        script_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        ttk.Label(script_frame, text="Script SQL:").grid(row=0, column=0, padx=5, pady=5)
        self.script_path_var = tk.StringVar()
        ttk.Entry(script_frame, textvariable=self.script_path_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(script_frame, text="Parcourir", command=self.browse_script).grid(row=0, column=2, padx=5, pady=5)

        ttk.Button(script_frame, text="Exécuter Script", command=self.execute_script).grid(row=1, column=0, columnspan=3, pady=10)

        # Table des serveurs
        columns = ("Selection", "Serveur", "Statut")
        self.server_table = ttk.Treeview(script_frame, columns=columns, show="headings", height=10)
        self.server_table.grid(row=2, column=0, columnspan=3, pady=5)

        # Définir les en-têtes des colonnes
        self.server_table.heading("Selection", text="Sélection")
        self.server_table.heading("Serveur", text="Serveur (Nom et Host)")
        self.server_table.heading("Statut", text="Statut")

        # Ajouter une case à cocher dans la colonne "Sélection"
        self.server_table.column("Selection", width=50, anchor="center")
        self.server_table.column("Serveur", width=300, anchor="w")
        self.server_table.column("Statut", width=100, anchor="center")

        # Gestion des événements de clic sur la table
        self.server_table.bind("<ButtonRelease-1>", self.toggle_checkbox)

        # Remplir la table avec les serveurs configurés
        self.update_server_table()

    def toggle_checkbox(self, event):
        region = self.server_table.identify_region(event.x, event.y)
        if region != "cell":
            return

        column = self.server_table.identify_column(event.x)
        if column != "#1":  # Vérifier si la colonne cliquée est "Sélection"
            return

        item = self.server_table.identify_row(event.y)
        if not item:
            return

        values = self.server_table.item(item, "values")
        server_name = values[1].split(" (")[0]
        current_state = self.check_vars[server_name].get()
        new_state = not current_state
        self.check_vars[server_name].set(new_state)

        checkbox_char = "☑" if new_state else "☐"
        self.server_table.item(item, values=(checkbox_char, values[1], values[2]))

    def add_or_update_server(self):
        server_name = self.server_name_var.get()
        if not server_name:
            messagebox.showerror("Erreur", "Le nom du serveur est requis.")
            return

        server = {
            'host': self.host_var.get(),
            'user': self.user_var.get(),
            'password': self.password_var.get(),
            'database': self.database_var.get(),
            'ssl_ca': self.ssl_ca_var.get()
        }

        self.config[server_name] = server
        save_config(self.config)
        self.update_server_table()
        self.clear_server_fields()

    def delete_server(self):
        selected_items = self.server_table.selection()
        if not selected_items:
            messagebox.showerror("Erreur", "Aucun serveur sélectionné.")
            return

        for item in selected_items:
            server_name = self.server_table.item(item, "values")[1].split(" (")[0]
            del self.config[server_name]

        save_config(self.config)
        self.update_server_table()

    def update_server_table(self):
        for row in self.server_table.get_children():
            self.server_table.delete(row)

        self.check_vars.clear()

        for server_name, server_info in self.config.items():
            server_display = f"{server_name} ({server_info['host']})"
            check_var = tk.BooleanVar(value=False)
            self.check_vars[server_name] = check_var
            self.server_table.insert("", "end", values=("☐", server_display, ""))

    def clear_server_fields(self):
        self.server_name_var.set("")
        self.host_var.set("")
        self.user_var.set("")
        self.password_var.set("")
        self.database_var.set("")
        self.ssl_ca_var.set("")

    def browse_script(self):
        file_path = filedialog.askopenfilename(filetypes=[("Fichiers SQL", "*.sql")])
        if file_path:
            self.script_path_var.set(file_path)

    def browse_ssl_cert(self):
        file_path = filedialog.askopenfilename(initialdir="certif", filetypes=[("Fichiers PEM", "*.pem")])
        if file_path:
            self.ssl_ca_var.set(file_path)

    # Fonction pour supprimer les commentaires SQL

    def execute_sql(self, server, script_path):
        try:
            ssl_ca = server.get("ssl_ca", "")
            if not os.path.isfile(ssl_ca):
                return False, f"Le fichier de certificat '{ssl_ca}' n'existe pas."

            connection = MySQLdb.connect(
                host=server['host'],
                user=server['user'],
                passwd=server['password'],
                db=server['database'],
                ssl={"ca": ssl_ca}
            )
            cursor = connection.cursor()

            with open(script_path, 'r', encoding='utf-8') as file:
                sql_script = file.read()

            # Supprimer les commentaires du script SQL
            sql_script = remove_comments(sql_script)

            # Diviser le script en requêtes individuelles
            queries = [query.strip() for query in sql_script.split(';') if query.strip()]

            # Exécuter chaque requête
            for query in queries:
                cursor.execute(query)

            connection.commit()
            cursor.close()
            connection.close()
            return True, "Script exécuté avec succès."
        except MySQLdb.OperationalError as e:
            return False, f"Erreur de connexion : {str(e)}"
        except Exception as e:
            return False, f"Erreur inattendue : {str(e)}"

    def execute_script(self):
        script_path = self.script_path_var.get()
        if not script_path:
            messagebox.showerror("Erreur", "Veuillez sélectionner un script SQL.")
            return

        # Extraire le nom du script (sans le chemin complet)
        script_name = os.path.basename(script_path)

        # Récupérer les serveurs sélectionnés
        selected_servers = []
        for item in self.server_table.get_children():
            values = self.server_table.item(item, "values")
            server_name = values[1].split(" (")[0]
            check_var = self.check_vars[server_name]
            if check_var.get():
                selected_servers.append(server_name)

        if not selected_servers:
            messagebox.showerror("Erreur", "Veuillez sélectionner au moins un serveur.")
            return

        results = []
        all_success = True

        for server_name in selected_servers:
            server = self.config[server_name]
            success, message = self.execute_sql(server, script_path)
            status_icon = "✅" if success else "❌"
            self.update_status(server_name, status_icon)
            results.append(f"{server_name}: {'Succès' if success else 'Échec'} - {message}")
            if not success:
                all_success = False

        result_message = "\n".join(results)
        messagebox.showinfo("Résultats", result_message)

        # Envoyer un e-mail si tous les scripts ont réussi
        if all_success:
            self.send_success_email(script_name)

    def send_success_email(self, script_name):
        recipients = load_recipients().get("recipients", [])
        if not recipients:
            messagebox.showwarning("Avertissement", "Aucun destinataire défini dans le fichier JSON.")
            return

        try:
            email_body_template = load_email_message()
            email_body = email_body_template.replace("%1", script_name)
            subject = "Scripts SQL Exécutés avec Succès"

            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            sender_email = "votre_email@gmail.com"  # Remplacez par votre e-mail
            sender_password = "votre_mot_de_passe"  # Remplacez par votre mot de passe

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = subject
            msg.attach(MIMEText(email_body, 'plain'))

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipients, msg.as_string())

            messagebox.showinfo("Succès", "E-mail envoyé avec succès aux destinataires.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de l'envoi de l'e-mail : {str(e)}")

    def update_status(self, server_name, status_icon):
        for item in self.server_table.get_children():
            values = self.server_table.item(item, "values")
            if values[1].startswith(server_name):
                self.server_table.item(item, values=(values[0], values[1], status_icon))
                break


# Fenêtre d'authentification
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentification")
        self.root.geometry("300x150")
        self.root.resizable(False, False)

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="Nom d'utilisateur:").grid(row=0, column=0, padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.username_var).grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.root, text="Mot de passe:").grid(row=1, column=0, padx=10, pady=10)
        ttk.Entry(self.root, textvariable=self.password_var, show="*").grid(row=1, column=1, padx=10, pady=10)

        ttk.Button(self.root, text="Se connecter", command=self.authenticate).grid(row=2, column=0, columnspan=2, pady=10)

    # Vérifier les identifiants avec un hachage salé
    # Vérifier les identifiants
    def authenticate(self):
        # Récupérer les valeurs des champs
        username = self.username_var.get()
        password = self.password_var.get()

        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et un mot de passe.")
            return

        # Vérifier les identifiants
        if authenticate(username, password):
            self.root.destroy()  # Fermer la fenêtre d'authentification
            main_app_root = tk.Tk()  # Ouvrir l'application principale
            app = SQLExecutorApp(main_app_root)
            main_app_root.mainloop()
        else:
            messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect.")


# Lancer l'application
if __name__ == "__main__":
    root = tk.Tk()
    login_window = LoginWindow(root)
    root.mainloop()