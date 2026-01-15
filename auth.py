# auth.py
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from datetime import datetime

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
login_manager = LoginManager()

class User(UserMixin):
    def __init__(self, id, email, first_name, last_name):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, first_name, last_name FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['firstName']
        last_name = request.form['lastName']
        email = request.form['email']
        password = request.form['password']
        
        # Validate inputs
        if not all([first_name, last_name, email, password]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('auth.register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long!', 'danger')
            return redirect(url_for('auth.register'))
        
        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Save to database
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (first_name, last_name, email, password_hash, datetime.now()))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password_hash, first_name, last_name FROM users WHERE email = ?", (email,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and bcrypt.check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1], user_data[3], user_data[4])
            login_user(user, remember='remember' in request.form)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)