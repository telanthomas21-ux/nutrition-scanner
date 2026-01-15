from flask import Flask, render_template, request, jsonify, redirect, session, flash
from functools import wraps
import sqlite3
import pickle
import numpy as np
import os
from datetime import datetime
import qrcode
from io import BytesIO
import base64
import hashlib
import urllib.parse
import re

app = Flask(__name__, template_folder='templates')
app.secret_key = 'nutrition-scanner-secret-key-2024'  # Change in production

# Initialize database
import database
database.init_db()

# Load or train model
if os.path.exists('health_model.pkl'):
    with open('health_model.pkl', 'rb') as f:
        model = pickle.load(f)
else:
    model = database.train_ml_model()

# Helper functions
def get_product(product_id):
    """Get product data from database"""
    product_id = str(product_id).strip()  # normalize
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE UPPER(id) = UPPER(?)", (product_id,))
    product = cursor.fetchone()
    conn.close()
    return product

def is_admin():
    """Check if current user is admin"""
    if 'user_id' not in session:
        return False
    # Check database to ensure admin status is still valid
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == 1

def get_user_health(user_id):
    """Get user's health data"""
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_health WHERE user_id = ?", (user_id,))
    health_data = cursor.fetchone()
    conn.close()
    return health_data

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next_url'] = request.url
            flash('Please login first to access this feature', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next_url'] = request.url
            flash('Please login first', 'warning')
            return redirect('/login')
        if not is_admin():
            flash('Admin access required!', 'danger')
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

# Template filters
@app.template_filter('healthy_badge')
def healthy_badge(is_healthy):
    if is_healthy == 1:
        return '<span class="badge bg-success">HEALTHY</span>'
    else:
        return '<span class="badge bg-danger">RISKY</span>'

@app.template_filter('healthy_stars')
def healthy_stars(is_healthy):
    if is_healthy == 1:
        return '⭐⭐⭐⭐⭐ <span class="text-success">(Excellent)</span>'
    else:
        return '⭐☆☆☆☆ <span class="text-danger">(Poor)</span>'

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')
@app.route('/product', methods=['POST'])

def product_lookup():
    product_id = request.form.get('product_id', '').strip()
    if not product_id:
        flash('Please enter a product ID.', 'warning')
        return redirect('/')

    product = get_product(product_id)
    if not product:
        flash(f'Product "{product_id}" not found!', 'danger')
        return redirect('/')

    # Reuse your product page template
    return render_template('product.html', product=product)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        first_name = request.form.get('firstName', '').strip()
        last_name = request.form.get('lastName', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        # Validate
        if not all([first_name, last_name, email, password]):
            flash('All fields are required!', 'danger')
            return redirect('/register')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'danger')
            return redirect('/register')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Save to database
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (first_name, last_name, email, password_hash, datetime.now()))
            
            # Get user ID
            user_id = cursor.lastrowid
            
            # Create health profile
            cursor.execute('''
                INSERT INTO user_health (user_id, cholesterol_level, sugar_level)
                VALUES (?, 180, 100)
            ''', (user_id,))
            
            conn.commit()
            
            # Auto login after registration
            session['user_id'] = user_id
            session['user_name'] = f"{first_name} {last_name}"
            session['user_email'] = email
            session['is_admin'] = False  # New registrations are not admin
            
            flash('Registration successful! Welcome to Nutrition Scanner!', 'success')
            return redirect('/')
            
        except sqlite3.IntegrityError:
            flash('Email already registered! Please use another email.', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        # Simple validation
        if not email or not password:
            flash('Please enter both email and password', 'danger')
            return redirect('/login')
        
        # Hash password for comparison
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Check credentials
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, first_name, last_name, is_admin FROM users 
            WHERE email = ? AND password_hash = ?
        ''', (email, password_hash))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['user_name'] = f"{user[1]} {user[2]}"
            session['user_email'] = email
            session['is_admin'] = user[3] == 1  # Store admin status in session
            
            # Redirect admin users to admin dashboard, others to home
            if user[3] == 1:  # is_admin == 1
                flash('Admin login successful! Welcome to the dashboard.', 'success')
                return redirect('/admin')
            else:
                # Redirect to next URL if exists (for regular users)
                next_url = session.pop('next_url', None)
                flash('Login successful!', 'success')
                return redirect(next_url or '/')
        else:
            flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect('/')

@app.route('/profile')
@login_required
def profile():
    # Get user data
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.first_name, u.last_name, u.email, u.created_at,
               uh.cholesterol_level, uh.sugar_level
        FROM users u
        LEFT JOIN user_health uh ON u.id = uh.user_id
        WHERE u.id = ?
    ''', (session['user_id'],))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return render_template('profile.html', user=user_data)
    return redirect('/')

# Product page - accepts both IDs and names
@app.route('/p/<product_identifier>')
def product_page(product_identifier):
    """Product page - accepts both IDs and names"""
    product_identifier = urllib.parse.unquote(product_identifier).strip()

    # Always try exact ID match first
    product = get_product(product_identifier)
    if not product:
        # Fallback: try name match
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM products WHERE LOWER(name) LIKE ? LIMIT 1",
            (f'%{product_identifier.lower()}%',)
        )
        product = cursor.fetchone()
        conn.close()

    if product:
        return render_template('product.html', product=product)

    flash(f'Product "{product_identifier}" not found!', 'danger')
    return redirect('/')

@app.route('/compare/<product1>/vs/<product2>')
def compare_products(product1, product2):
    product1 = urllib.parse.unquote(product1).strip()
    product2 = urllib.parse.unquote(product2).strip()

    def get_product_by_id_or_name(search_term):
        search_term = search_term.strip()
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()

        # 1) exact ID (handles PROD001, ASC220, etc.)
        cursor.execute(
            "SELECT * FROM products WHERE UPPER(id) = UPPER(?)",
            (search_term,)
        )
        product = cursor.fetchone()

        # 2) fallback: name contains
        if not product:
            cursor.execute(
                "SELECT * FROM products WHERE LOWER(name) LIKE ? LIMIT 1",
                (f'%{search_term.lower()}%',)
            )
            product = cursor.fetchone()

        conn.close()
        return product

    product1_data = get_product_by_id_or_name(product1)
    product2_data = get_product_by_id_or_name(product2)

    if not product1_data or not product2_data:
        flash('One or both products not found!', 'danger')
        return redirect('/')

    return render_template('compare.html',
                           product1=product1_data,
                           product2=product2_data)


# Search API
@app.route('/search')
def search_results():
    """Search results page - shows products containing search term anywhere"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect('/')
    
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    
    # Search for products containing the query anywhere in name or ID
    cursor.execute('''
        SELECT * FROM products 
        WHERE LOWER(name) LIKE ? OR LOWER(id) LIKE ?
        ORDER BY 
            CASE 
                WHEN LOWER(name) LIKE ? THEN 1  -- Name starts with
                WHEN LOWER(id) = ? THEN 2       -- Exact ID match
                WHEN LOWER(id) LIKE ? THEN 3    -- ID starts with
                WHEN LOWER(name) LIKE ? THEN 4  -- Name contains (not at start)
                ELSE 5
            END,
            name
    ''', (
        f'%{query.lower()}%',  # Name contains anywhere
        f'%{query.lower()}%',  # ID contains anywhere
        f'{query.lower()}%',   # For ordering - name starts with
        query.lower(),         # For ordering - exact ID match
        f'{query.lower()}%',   # For ordering - ID starts with
        f'%{query.lower()}%'   # For ordering - name contains anywhere
    ))
    
    products = cursor.fetchall()
    conn.close()
    
    return render_template('search.html', query=query, products=products)


@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    product_id = request.form['product_id']
    product = get_product(product_id)
    
    if not product:
        flash('Product not found!', 'danger')
        return redirect('/')
    
    # Get user inputs
    user_age = int(request.form.get('age', 30))
    user_weight = float(request.form.get('weight', 70))
    user_bp = float(request.form.get('bp', 120))
    user_sugar = float(request.form.get('sugar_level', 100))
    user_cholesterol = float(request.form.get('cholesterol', 180))
    
    # Health conditions
    has_diabetes = request.form.get('diabetes') == 'on'
    has_cholesterol = request.form.get('cholesterol_cond') == 'on'
    has_hypertension = request.form.get('hypertension') == 'on'
    has_heart_disease = request.form.get('heart_disease') == 'on'
    
    # Update user health data in database
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO user_health 
        (user_id, cholesterol_level, sugar_level, last_updated)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ''', (session['user_id'], user_cholesterol, user_sugar))
    
    # Save scan to history
    cursor.execute('''
        INSERT INTO scan_history (user_id, product_id, scanned_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (session['user_id'], product_id))
    
    conn.commit()
    conn.close()
    
    # Prepare user conditions for analysis
    user_conditions = {
        'age': user_age,
        'weight': user_weight,
        'bp': user_bp,
        'sugar_level': user_sugar,
        'cholesterol_level': user_cholesterol,
        'diabetes': has_diabetes,
        'cholesterol_condition': has_cholesterol,
        'hypertension': has_hypertension,
        'heart_disease': has_heart_disease
    }
    
    # Analyze product
    is_safe, warnings = analyze_product(product, user_conditions)
    
    return render_template('analysis.html', 
                         product=product,
                         is_safe=is_safe,
                         user_conditions=user_conditions,
                         warnings=warnings)

def analyze_product(product, user_conditions):
    """Analyze product based on user health conditions"""
    sugar, fat, sodium, calories = product[3], product[4], product[6], product[2]
    warnings = []
    is_safe = 1  # Start with safe
    
    # Cholesterol analysis
    user_cholesterol = user_conditions.get('cholesterol_level', 180)
    if user_conditions.get('cholesterol_condition') and fat > 10:
        warnings.append("High fat content not suitable for cholesterol patients")
        is_safe = 0
    elif user_cholesterol > 200 and fat > 15:
        warnings.append("High fat content with elevated cholesterol levels")
        is_safe = 0
    elif user_cholesterol > 240 and fat > 5:
        warnings.append("Fat content may affect very high cholesterol")
        is_safe = 0.5
    
    # Diabetes analysis
    user_sugar = user_conditions.get('sugar_level', 100)
    if user_conditions.get('diabetes') and sugar > 15:
        warnings.append("High sugar content not suitable for diabetics")
        is_safe = 0
    elif user_sugar > 180 and sugar > 10:
        warnings.append("Sugar content may spike high blood sugar")
        is_safe = 0
    elif user_sugar > 140 and sugar > 20:
        warnings.append("Very high sugar content for elevated blood sugar")
        is_safe = 0
    
    # Hypertension analysis
    if user_conditions.get('hypertension') and sodium > 300:
        warnings.append("High sodium content not suitable for hypertension")
        is_safe = 0
    elif user_conditions.get('bp', 120) > 140 and sodium > 200:
        warnings.append("Sodium content may affect high blood pressure")
        is_safe = 0.5
    
    # General health thresholds
    if sugar > 25:
        warnings.append("Very high sugar content (>25g)")
        is_safe = min(is_safe, 0.5)
    if fat > 20:
        warnings.append("Very high fat content (>20g)")
        is_safe = min(is_safe, 0.5)
    if sodium > 500:
        warnings.append("Very high sodium content (>500mg)")
        is_safe = min(is_safe, 0.5)
    
    # Age considerations
    if user_conditions.get('age', 30) > 60:
        if sodium > 300:
            warnings.append("High sodium for elderly individuals")
            is_safe = min(is_safe, 0.5)
        if sugar > 20:
            warnings.append("High sugar for elderly individuals")
            is_safe = min(is_safe, 0.5)
    
    return is_safe, warnings

@app.route('/api/autocomplete')
def autocomplete():
    """Autocomplete for product search - shows products containing the search term anywhere"""
    query = request.args.get('q', '').strip().lower()
    results = []

    if not query:
        return jsonify(results)

    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()

    # Search for products CONTAINING the query anywhere in name or ID
    cursor.execute("""
        SELECT id, name, calories, is_healthy
        FROM products
        WHERE LOWER(name) LIKE ? OR LOWER(id) LIKE ?
        ORDER BY 
            CASE 
                WHEN LOWER(name) LIKE ? THEN 1  -- Name starts with query (highest priority)
                WHEN LOWER(id) = ? THEN 2       -- Exact ID match
                WHEN LOWER(id) LIKE ? THEN 3    -- ID starts with query
                WHEN LOWER(name) LIKE ? THEN 4  -- Name contains query (not at start)
                ELSE 5
            END,
            name
        LIMIT 15
    """, (
        f'%{query}%',     # Name contains query anywhere
        f'%{query}%',     # ID contains query anywhere
        f'{query}%',      # For ordering - name starts with
        query,            # For ordering - exact ID match
        f'{query}%',      # For ordering - ID starts with
        f'%{query}%'      # For ordering - name contains anywhere
    ))
    
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        results.append({
            "id": row[0],
            "name": row[1],
            "calories": row[2],
            "is_healthy": row[3]
        })

    return jsonify(results)
# Admin Routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    # Get statistics
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM products")
    total_products = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = DATE('now')")
    new_users_today = cursor.fetchone()[0]
    
    # Get recent scans
    cursor.execute('''
        SELECT sh.scanned_at, p.name, u.email 
        FROM scan_history sh
        JOIN products p ON sh.product_id = p.id
        JOIN users u ON sh.user_id = u.id
        ORDER BY sh.scanned_at DESC LIMIT 10
    ''')
    recent_scans = cursor.fetchall()
    
    # Get recent users
    cursor.execute("SELECT id, first_name, last_name, email, created_at FROM users ORDER BY created_at DESC LIMIT 10")
    recent_users = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_products=total_products,
                         total_scans=total_scans,
                         new_users_today=new_users_today,
                         recent_scans=recent_scans,
                         recent_users=recent_users)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Manage users"""
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, first_name, last_name, email, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/products')
@admin_required
def admin_products():
    """Manage products"""
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products ORDER BY name")
    products = cursor.fetchall()
    conn.close()
    
    return render_template('admin_products.html', products=products)

@app.route('/admin/qr-codes')
@admin_required
def admin_qr_codes():
    """Generate and manage QR codes"""
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM products ORDER BY name")
    products = cursor.fetchall()
    conn.close()
    
    # Ensure products is always a list, even if empty
    products = products or []
    
    return render_template('admin_qr.html', products=products)

@app.route('/admin/generate-qr/<product_id>')
@admin_required
def generate_product_qr(product_id):
    """Generate QR code for a product"""
    product = get_product(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    # Generate QR code with product URL
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # Get local IP address for QR code
    import socket
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "localhost"
    
    local_ip = get_local_ip()
    base_url = f"http://{local_ip}:5000"
    product_url = f"{base_url}/p/{product_id}"
    qr.add_data(product_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return jsonify({
        'qr_code': img_str,
        'product_id': product_id,
        'product_name': product[1],
        'product_url': product_url
    })

@app.route('/admin/add-product', methods=['POST'])
@admin_required
def admin_add_product():
    """Add new product (admin)"""
    try:
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        
        product_id = request.form['id'].strip().upper()
        name = request.form['name'].strip()
        calories = int(request.form['calories'])
        sugar = float(request.form['sugar'])
        fat = float(request.form['fat'])
        protein = float(request.form['protein'])
        sodium = float(request.form['sodium'])
        chemicals = request.form.get('chemicals', '').strip()
        is_healthy = 1 if request.form.get('is_healthy') == 'on' else 0
        
        cursor.execute("""
            INSERT OR REPLACE INTO products 
            (id, name, calories, sugar, fat, protein, sodium, chemicals, is_healthy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (product_id, name, calories, sugar, fat, protein, sodium, chemicals, is_healthy))
        
        conn.commit()
        flash(f'Product "{name}" added successfully!', 'success')
        
    except Exception as e:
        flash(f'Error adding product: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect('/admin/products')

@app.route('/admin/edit-product/<product_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(product_id):
    """Edit existing product"""
    if request.method == 'POST':
        try:
            conn = sqlite3.connect('nutrition.db')
            cursor = conn.cursor()
            
            name = request.form['name'].strip()
            calories = int(request.form['calories'])
            sugar = float(request.form['sugar'])
            fat = float(request.form['fat'])
            protein = float(request.form['protein'])
            sodium = float(request.form['sodium'])
            chemicals = request.form.get('chemicals', '').strip()
            is_healthy = 1 if request.form.get('is_healthy') == 'on' else 0
            
            cursor.execute("""
                UPDATE products 
                SET name=?, calories=?, sugar=?, fat=?, protein=?, sodium=?, chemicals=?, is_healthy=?
                WHERE id=?
            """, (name, calories, sugar, fat, protein, sodium, chemicals, is_healthy, product_id))
            
            conn.commit()
            flash(f'Product "{name}" updated successfully!', 'success')
            
        except Exception as e:
            flash(f'Error updating product: {str(e)}', 'danger')
        finally:
            conn.close()
        
        return redirect('/admin/products')
    
    # GET request - show edit form
    product = get_product(product_id)
    if not product:
        flash('Product not found!', 'danger')
        return redirect('/admin/products')
    
    return render_template('admin_edit_product.html', product=product)

@app.route('/admin/delete-product/<product_id>')
@admin_required
def admin_delete_product(product_id):
    """Delete product"""
    try:
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM products WHERE id = ?", (product_id,))
        product_name = cursor.fetchone()[0]
        
        cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
        conn.commit()
        
        flash(f'Product "{product_name}" deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting product: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect('/admin/products')

@app.route('/admin/toggle-admin/<user_id>')
@admin_required
def toggle_admin(user_id):
    """Toggle admin status for user"""
    try:
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        current_status = cursor.fetchone()[0]
        new_status = 0 if current_status == 1 else 1
        
        cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        
        status_text = "Admin" if new_status == 1 else "Regular User"
        flash(f'User status changed to {status_text}', 'success')
    except Exception as e:
        flash(f'Error updating user: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect('/admin/users')

@app.route('/admin/delete-user/<user_id>')
@admin_required
def admin_delete_user(user_id):
    """Delete user"""
    # Prevent deleting yourself
    if int(user_id) == session['user_id']:
        flash('Cannot delete your own account!', 'danger')
        return redirect('/admin/users')
    
    try:
        conn = sqlite3.connect('nutrition.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user_email = cursor.fetchone()[0]
        
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        
        flash(f'User "{user_email}" deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect('/admin/users')



# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)