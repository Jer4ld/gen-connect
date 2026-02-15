
import sqlite3
import os
from app import app, db


# Based on app.py: app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///genconnect.db'
# Flask-SQLAlchemy > 3.0 puts relative paths in instance folder
db_path = os.path.join('instance', 'genconnect.db')
if not os.path.exists(db_path):
    # Fallback if not in instance
    db_path = 'genconnect.db'


def update_database():
    print(f"Connecting to database at {os.path.abspath(db_path)}...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("PRAGMA table_info(activities)")
        columns = [info[1] for info in cursor.fetchall()]
        print(f"Current columns in activities: {columns}")
        
        # Add new columns if missing
        new_columns = {
            'creator_id': 'INTEGER NOT NULL DEFAULT 1',
            'quota': 'INTEGER DEFAULT 20',
            'image': 'VARCHAR(255)',
            'instructions': 'TEXT'
        }

        for col, definition in new_columns.items():
            if col not in columns:
                print(f"Adding {col} column to activities table...")
                cursor.execute(f"ALTER TABLE activities ADD COLUMN {col} {definition}")
            else:
                print(f"{col} column already exists.")
            
        conn.commit()
        print("Schema update committed.")
        
    except Exception as e:
        print(f"Error updating schema: {e}")
        conn.rollback()
    finally:
        conn.close()

    # Create activity_participants table using raw SQL to be sure
    print("Creating table activity_participants...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_participants (
            id INTEGER PRIMARY KEY,
            activity_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(activity_id) REFERENCES activities(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        conn.commit()
        print("Table activity_participants created (or already exists).")
    except Exception as e:
        print(f"Error creating table: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    update_database()
