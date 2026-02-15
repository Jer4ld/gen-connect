
import sqlite3
import os
from app import app, db

# Based on app.py: app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///genconnect.db'
# This usually maps to the root directory
db_path = 'genconnect.db'

def update_database():
    print(f"Connecting to database at {os.path.abspath(db_path)}...")
    
    if not os.path.exists(db_path):
        print(f"WARNING: Database file not found at {db_path}!")
        print("Checking if it's in instance folder as fallback...")
        instance_path = os.path.join('instance', 'genconnect.db')
        if os.path.exists(instance_path):
            print(f"Found in instance folder: {instance_path}")
            # If found in instance but config says root, we might be running from different CWD
            # But let's stick to the file at root if config is 'sqlite:///genconnect.db' 
            # and we are running from project root.
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if creator_id exists
        cursor.execute("PRAGMA table_info(activities)")
        columns = [info[1] for info in cursor.fetchall()]
        print(f"Current columns in activities: {columns}")
        
        if 'creator_id' not in columns:
            print("Adding creator_id column to activities table...")
            cursor.execute("ALTER TABLE activities ADD COLUMN creator_id INTEGER NOT NULL DEFAULT 1")
        else:
            print("creator_id column already exists.")
            
        if 'quota' not in columns:
            print("Adding quota column to activities table...")
            cursor.execute("ALTER TABLE activities ADD COLUMN quota INTEGER DEFAULT 20")
        else:
            print("quota column already exists.")
            
        conn.commit()
        print("Schema update committed.")
        
    except Exception as e:
        print(f"Error updating schema: {e}")
        conn.rollback()
    finally:
        conn.close()

    # Use Flask-SQLAlchemy to create any MISSING tables (like activities_users)
    print("Creating missing tables (activities_users)...")
    with app.app_context():
        # Force the DB URI to match what we expect if needed, but app context should load it
        print(f"App DB URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        db.create_all()
        print("db.create_all() executed.")

if __name__ == "__main__":
    update_database()
