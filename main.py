import os
import webbrowser
import folium
import tkinter as tk
import sqlite3
import bcrypt

conn = sqlite3.connect('users.db')

cursor = conn.cursor()
conn.commit()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
''')

def create_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
def show_map():
    map_latitude = 14.26271
    map_longitude = 121.39747
    m = folium.Map(location=[map_latitude, map_longitude], zoom_start=15)
    map_file = 'map.html'
    m.save(map_file)
    map_view = tk.Toplevel(root)
    map_view.title("Classmates' Locations")
    map_view.geometry('500x300')
    browser = tk.Frame(map_view)
    browser.pack(fill=tk.BOTH, expand=tk.YES)
    web_view = tk.Label(browser)
    web_view.pack(fill=tk.BOTH, expand=tk.YES)
    map_url = os.path.abspath(map_file)
    webbrowser.open('file://' + map_url)

def load_map():
    load_map_btn.destroy()  # Remove the load map button
    sign_up_btn.pack()
    log_in_btn.pack()

def sign_up():
    def create_new_user():
        username = username_entry.get()
        password = password_entry.get()
        create_user(username, password)
        sign_up_window.destroy()

    sign_up_window = tk.Toplevel(root)
    sign_up_window.title("Sign Up")
    sign_up_window.geometry('300x150')

    username_label = tk.Label(sign_up_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(sign_up_window)
    username_entry.pack()

    password_label = tk.Label(sign_up_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(sign_up_window, show="*")
    password_entry.pack()

    sign_up_btn = tk.Button(sign_up_window, text="Sign Up", command=create_new_user)
    sign_up_btn.pack()

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
            # Handle incorrect credentials here (e.g., display an error message)
            print("Incorrect username or password")

    log_in_window = tk.Toplevel(root)
    log_in_window.title("Log In")
    log_in_window.geometry('300x150')

    username_label = tk.Label(log_in_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(log_in_window)
    username_entry.pack()

    password_label = tk.Label(log_in_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(log_in_window, show="*")
    password_entry.pack()

    log_in_btn = tk.Button(log_in_window, text="Log In", command=verify_user)
    log_in_btn.pack()

root = tk.Tk()
root.title("GPS Tracker")

load_map_btn = tk.Button(root, text="Load Map", command=load_map)
load_map_btn.pack()

sign_up_btn = tk.Button(root, text="Sign Up", command=sign_up)
log_in_btn = tk.Button(root, text="Log In", command=log_in)

root.mainloop()
