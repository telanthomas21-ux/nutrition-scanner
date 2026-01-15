import sqlite3
from datetime import datetime
import pickle

def init_db():
    """Initialize database with all required tables"""
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    
    # Products Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            calories INTEGER NOT NULL,
            sugar REAL NOT NULL,
            fat REAL NOT NULL,
            protein REAL NOT NULL,
            sodium REAL NOT NULL,
            chemicals TEXT,
            is_healthy INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            age INTEGER,
            weight REAL,
            height REAL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # User Health Profile Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_health (
            user_id INTEGER PRIMARY KEY,
            cholesterol_level REAL DEFAULT 180,
            sugar_level REAL DEFAULT 100,
            blood_pressure_systolic INTEGER DEFAULT 120,
            blood_pressure_diastolic INTEGER DEFAULT 80,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # User Health Conditions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            condition_type TEXT NOT NULL,
            condition_name TEXT NOT NULL,
            diagnosed_date DATE,
            severity TEXT,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Scan History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id TEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            analysis_result TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
        )
    ''')
    
    # Favorites Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
            UNIQUE(user_id, product_id)
        )
    ''')
    
    # Insert sample products
    sample_products = [
        ('PROD001', 'Fresh Apple', 52, 10.4, 0.2, 0.3, 1, '', 1),
        ('PROD002', 'Chocolate Bar', 535, 65.0, 30.0, 5.0, 50, 'Artificial Sweetener, Preservatives', 0),
        ('PROD003', 'Whole Wheat Bread', 247, 4.3, 3.2, 10.0, 450, '', 1),
        ('PROD004', 'Greek Yogurt', 59, 4.0, 0.4, 10.0, 36, '', 1),
        ('PROD005', 'Potato Chips', 536, 0.4, 34.0, 7.0, 480, 'MSG, Artificial Flavors', 0),
        ('PROD006', 'Almonds', 575, 4.4, 49.0, 21.0, 1, '', 1),
        ('PROD007', 'Orange Juice', 45, 8.4, 0.2, 0.7, 1, '', 1),
        ('PROD008', 'Cheese Pizza', 285, 3.8, 10.0, 12.0, 640, '', 0),
        ('PROD009', 'Salmon Fillet', 206, 0.0, 13.0, 22.0, 59, '', 1),
        ('PROD010', 'Soda Can', 150, 39.0, 0.0, 0.0, 30, 'Artificial Colors, High Fructose Corn Syrup', 0)
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO products 
        (id, name, calories, sugar, fat, protein, sodium, chemicals, is_healthy)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_products)
    
    # Create demo admin user (password: admin123)
    import hashlib
    admin_password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO users 
        (first_name, last_name, email, password_hash, is_admin)
        VALUES (?, ?, ?, ?, ?)
    ''', ('Admin', 'User', 'admin@nutriscan.com', admin_password_hash, 1))
    
    # Create demo regular user (password: demo123)
    demo_password_hash = hashlib.sha256('demo123'.encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO users 
        (first_name, last_name, email, password_hash, is_admin)
        VALUES (?, ?, ?, ?, ?)
    ''', ('Demo', 'User', 'demo@example.com', demo_password_hash, 0))
    
    # Add health data for demo user
    cursor.execute('SELECT id FROM users WHERE email = ?', ('demo@example.com',))
    demo_user = cursor.fetchone()
    if demo_user:
        demo_user_id = demo_user[0]
        cursor.execute('''
            INSERT OR IGNORE INTO user_health 
            (user_id, cholesterol_level, sugar_level, blood_pressure_systolic, blood_pressure_diastolic)
            VALUES (?, ?, ?, ?, ?)
        ''', (demo_user_id, 210, 110, 135, 85))
        
        # Add sample health conditions for demo user
        demo_conditions = [
            (demo_user_id, 'chronic', 'High Cholesterol', '2023-01-15', 'moderate', 'Managed with diet'),
            (demo_user_id, 'chronic', 'Borderline Diabetes', '2023-03-20', 'mild', 'Monitoring blood sugar')
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO user_conditions 
            (user_id, condition_type, condition_name, diagnosed_date, severity, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', demo_conditions)
    
    conn.commit()
    conn.close()
    
    # Train ML model
    train_ml_model()
    
    print("✅ Database initialized successfully with sample data!")
    print("📊 Products added: 10 sample products")
    print("👤 Demo users created:")
    print("   - Admin: admin@nutriscan.com / admin123")
    print("   - Regular: demo@example.com / demo123")

def train_ml_model():
    """Train simple rule-based model for health predictions"""
    print("🤖 Training health prediction model...")
    
    # Simple rule-based thresholds (no actual ML for simplicity)
    model_rules = {
        'sugar_threshold': 25,      # grams per serving
        'fat_threshold': 20,        # grams per serving
        'sodium_threshold': 400,    # mg per serving
        'calorie_threshold': 300,   # kcal per serving
        'protein_threshold': 10,    # grams per serving (good if above)
    }
    
    # Save model
    with open('health_model.pkl', 'wb') as f:
        pickle.dump(model_rules, f)
    
    print("✅ Model trained and saved as health_model.pkl")
    return model_rules

def get_product_stats():
    """Get statistics about products in database"""
    conn = sqlite3.connect('nutrition.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM products")
    total_products = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM products WHERE is_healthy = 1")
    healthy_products = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(calories), AVG(sugar), AVG(fat), AVG(protein), AVG(sodium) FROM products")
    averages = cursor.fetchone()
    
    conn.close()
    
    return {
        'total_products': total_products,
        'healthy_products': healthy_products,
        'avg_calories': averages[0],
        'avg_sugar': averages[1],
        'avg_fat': averages[2],
        'avg_protein': averages[3],
        'avg_sodium': averages[4]
    }

def backup_database():
    """Create a backup of the database"""
    import shutil
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"backup_nutrition_{timestamp}.db"
    shutil.copy2('nutrition.db', backup_file)
    print(f"✅ Database backed up as {backup_file}")
    return backup_file

def reset_database():
    """Reset database (WARNING: Deletes all data!)"""
    import os
    if os.path.exists('nutrition.db'):
        backup_database()
        os.remove('nutrition.db')
        print("🗑️ Database deleted. Run init_db() to create a fresh one.")

if __name__ == '__main__':
    init_db()
    
    # Show database statistics
    stats = get_product_stats()
    print("\n📈 Database Statistics:")
    print(f"   Total Products: {stats['total_products']}")
    print(f"   Healthy Products: {stats['healthy_products']}")
    print(f"   Average Calories: {stats['avg_calories']:.1f} kcal")
    print(f"   Average Sugar: {stats['avg_sugar']:.1f} g")
    print(f"   Average Fat: {stats['avg_fat']:.1f} g")
    print(f"   Average Protein: {stats['avg_protein']:.1f} g")
    print(f"   Average Sodium: {stats['avg_sodium']:.1f} mg")
