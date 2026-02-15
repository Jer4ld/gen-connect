
from app import app, db, Activity, User

def fix_ownership():
    with app.app_context():
        print("Starting ownership fix...")
        
        # 1. Get a dummy user to be the new creator
        # We'll use the last dummy user to avoid conflict with the first few who might be participants
        dummy_creator = User.query.filter_by(username='dummy_user_20').first()
        if not dummy_creator:
            print("Error: dummy_user_20 not found. Run seed_activities.py first.")
            return

        print(f"Transferring ownership to: {dummy_creator.username} (ID: {dummy_creator.id})")

        # 2. List of seeded activity titles (from seed_activities.py)
        titles = [
            "Abstract Painting Workshop",
            "Knitting Circle for Beginners",
            "Gourmet Cooking Class: Italian",
            "Computer Basics: Email & Web",
            "Smartphone Security 101",
            "Video Calling with Family",
            "Morning Tai Chi in the Park",
            "Nature Photography Walk",
            "Community Gardening Day",
            "Food Bank Sorting",
            "Reading Buddies at Primary School",
            "Hospital Visitor Program"
        ]

        count = 0
        for title in titles:
            activity = Activity.query.filter_by(title=title).first()
            if activity:
                if activity.creator_id != dummy_creator.id:
                    activity.creator_id = dummy_creator.id
                    count += 1
                    print(f"Updated '{title}' -> Now owned by {dummy_creator.username}")
                else:
                    print(f"'{title}' is already owned by {dummy_creator.username}")
            else:
                print(f"Activity '{title}' not found.")

        try:
            db.session.commit()
            print(f"Successfully transferred {count} activities.")
        except Exception as e:
            db.session.rollback()
            print(f"Error during commit: {e}")

if __name__ == "__main__":
    fix_ownership()
