import os
import webbrowser
import folium
import tkinter as tk
import sqlite3
import bcrypt

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
''')
conn.commit()

def create_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()

def show_map():
    lspu_latitude = 14.2628364
    lspu_longitude = 121.39744944444445
    m = folium.Map(location=[lspu_latitude, lspu_longitude], zoom_start=15)

    # Folium Marker
    folium.Marker([lspu_latitude, lspu_longitude], popup='LSPU Main Location', icon=folium.Icon(color='purple')
                  ).add_to(m)
    map_file = 'map.html'
    m.save(map_file)
    map_view = tk.Toplevel(root)
    map_view.title("LSPU Campus Map")
    map_view.geometry('600x400')

    browser = tk.Frame(map_view)
    browser.pack(fill=tk.BOTH, expand=tk.YES)
    web_view = tk.Label(browser)
    web_view.pack(fill=tk.BOTH, expand=tk.YES)
    map_url = os.path.abspath(map_file)
    webbrowser.open('file://' + map_url)

def load_map():
    load_map_btn.destroy()  # Remove the load map button
    sign_up_btn.grid(row=0, column=0, pady=10, padx=10)
    log_in_btn.grid(row=0, column=1, pady=10, padx=10)

def sign_up():
    def create_new_user():
        username = username_entry.get()
        password = password_entry.get()
        create_user(username, password)
        sign_up_window.destroy()

    def verify_user():
        username = username_entry.get()
        password = password_entry.get()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        stored_password = cursor.fetchone()

        if stored_password and bcrypt.checkpw(password.encode(), stored_password[0].encode()):
            show_map()
            sign_up_window.destroy()
        else:
            print("Incorrect username or password")

    sign_up_window = tk.Toplevel(root)
    sign_up_window.title("Sign Up")
    sign_up_window.geometry("300x150")

    tk.Label(sign_up_window, text="Sign Up", font=('Helvetica', 16, 'bold')).pack(pady=10)

    username_label = tk.Label(sign_up_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(sign_up_window)
    username_entry.pack()

    password_label = tk.Label(sign_up_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(sign_up_window, show="*")
    password_entry.pack()

    log_in_btn = tk.Button(sign_up_window, text="Log In", command=create_new_user, bg='#2196F3', fg='white')
    log_in_btn.pack(pady=10)

    def verify_user():
        username = username_entry.get()
        password = password_entry.get()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        stored_password = cursor.fetchone()

        if stored_password and bcrypt.checkpw(password.encode(), stored_password[0].encode()):
            show_map()
            log_in_window.destroy()
        else:
            print("Incorrect username or password")

def log_in():
    def verify_user():
        username = username_entry.get()
        password = password_entry.get()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        stored_password = cursor.fetchone()

        if stored_password and bcrypt.checkpw(password.encode(), stored_password[0].encode()):
            show_map()
            log_in_window.destroy()
        else:
            print("Incorrect username or password")

    log_in_window = tk.Toplevel(root)
    log_in_window.title("Log In")
    log_in_window.geometry('300x200')

    tk.Label(log_in_window, text="Log In", font=('Helvetica', 16, 'bold')).pack(pady=10)

    username_label = tk.Label(log_in_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(log_in_window)
    username_entry.pack()

    password_label = tk.Label(log_in_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(log_in_window, show="*")
    password_entry.pack()

    log_in_btn = tk.Button(log_in_window, text="Log In", command=verify_user, bg='#2196F3', fg='white')
    log_in_btn.pack(pady=10)

    def verify_user():
        username = username_entry.get()
        password = password_entry.get()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        stored_password = cursor.fetchone()

        if stored_password and bcrypt.checkpw(password.encode(), stored_password[0].encode()):
            show_map()
            log_in_window.destroy()
        else:
            print("Incorrect username or password")

root = tk.Tk()
root.title("LSPU Campus Navigator")

load_map_btn = tk.Button(root, text="Load Map", command=load_map)
load_map_btn.pack()

sign_up_btn = tk.Button(root, text="Sign Up", command=sign_up)
log_in_btn = tk.Button(root, text="Log In", command=log_in)

root.mainloop()
