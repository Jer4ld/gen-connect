
import sqlite3
import os
from app import app, db

# Path to the database file
db_path = os.path.join('instance', 'genconnect.db')

def update_database():
    print(f"Connecting to database at {db_path}...")
    
    # Raw SQLite connection for ALTER TABLE
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if creator_id exists
        cursor.execute("PRAGMA table_info(activities)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'creator_id' not in columns:
            print("Adding creator_id column to activities table...")
            # We set a default value of 1 for existing rows (assumes user ID 1 exists/is valid owner)
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
        db.create_all()
        print("db.create_all() executed.")

if __name__ == "__main__":
    if os.path.exists(db_path):
        update_database()
        print("Database update complete.")
    else:
        print(f"Database file not found at {db_path}. Please ensure you ran the app at least once.")
