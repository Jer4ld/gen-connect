
from app import app, db, Activity, User, ActivityParticipant
from datetime import datetime
import random

def seed():
    with app.app_context():
        print("Starting seed process...")

        # 1. Ensure we have some dummy users to fill quotas
        dummy_users = []
        for i in range(1, 21):
            username = f'dummy_user_{i}'
            email = f'dummy{i}@example.com'
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, email=email, fullname=f'Dummy User {i}')
                user.set_password('password123')
                db.session.add(user)
                try:
                    db.session.commit()
                    print(f"Created user: {username}")
                except Exception as e:
                    db.session.rollback()
                    print(f"Skipped {username} due to error: {e}")
            dummy_users.append(user)
        
        # Reload users to get IDs
        dummy_users = User.query.filter(User.username.like('dummy_user_%')).all()
        if not dummy_users:
            print("Failed to create dummy users. Aborting.")
            return

        # 2. Define Activities (12 items, 4 categories, split evenly)
        categories = ["Hobbies", "Tech Help", "Outdoor", "Volunteer"]
        
        # Images map
        images = {
            "Hobbies": "https://loremflickr.com/800/400/art",
            "Tech Help": "https://loremflickr.com/800/400/tech",
            "Outdoor": "https://loremflickr.com/800/400/nature",
            "Volunteer": "https://loremflickr.com/800/400/volunteer"
        }

        activities_data = [
            # Hobbies
            {
                "title": "Abstract Painting Workshop",
                "category": "Hobbies",
                "location": "Community Art Center",
                "date": "15 Mar 2026",
                "time": "2:00 PM - 5:00 PM",
                "description": "Unleash your creativity with abstract art techniques. No prior experience needed.",
                "instructions": "All painting materials provided. Wear clothes you don't mind getting dirty.",
                "quota": 10,
                "is_full": True 
            },
            {
                "title": "Knitting Circle for Beginners",
                "category": "Hobbies",
                "location": "Library Meeting Room 2",
                "date": "20 Mar 2026",
                "time": "10:00 AM - 12:00 PM",
                "description": "Learn the basics of knitting in a relaxed, friendly environment.",
                "instructions": "Bring your own yarn and needles if you have them, otherwise some will be available.",
                "quota": 15,
                "is_full": False
            },
            {
                "title": "Gourmet Cooking Class: Italian",
                "category": "Hobbies",
                "location": "Culinary Institute Kitchen B",
                "date": "22 Mar 2026",
                "time": "6:00 PM - 9:00 PM",
                "description": "Master the art of making fresh pasta and authentic marinara sauce.",
                "instructions": "Ingredients provided. Please inform us of any dietary restrictions.",
                "quota": 8,
                "is_full": True
            },

            # Tech Help
            {
                "title": "Computer Basics: Email & Web",
                "category": "Tech Help",
                "location": "Tech Hub Lab 1",
                "date": "10 Mar 2026",
                "time": "9:00 AM - 11:00 AM",
                "description": "A slow-paced guide to navigating the internet and managing your email safely.",
                "instructions": "Laptops provided, or bring your own.",
                "quota": 12,
                "is_full": False
            },
            {
                "title": "Smartphone Security 101",
                "category": "Tech Help",
                "location": "Community Center Hall",
                "date": "18 Mar 2026",
                "time": "1:00 PM - 2:30 PM",
                "description": "Learn how to protect your personal information and avoid scams on your phone.",
                "instructions": "Bring your fully charged smartphone.",
                "quota": 20,
                "is_full": True
            },
            {
                "title": "Video Calling with Family",
                "category": "Tech Help",
                "location": "Senior Center Media Room",
                "date": "25 Mar 2026",
                "time": "10:30 AM - 12:00 PM",
                "description": "Learn to use Zoom, WhatsApp, and FaceTime to stay connected with loved ones.",
                "instructions": "Bring your tablet or smartphone.",
                "quota": 10,
                "is_full": False
            },

            # Outdoor
            {
                "title": "Morning Tai Chi in the Park",
                "category": "Outdoor",
                "location": "Central Park Pavilion",
                "date": "12 Mar 2026",
                "time": "7:00 AM - 8:00 AM",
                "description": "Gentle exercise to improve balance and flexibility. Suitable for all fitness levels.",
                "instructions": "Wear comfortable clothing and shoes.",
                "quota": 30,
                "is_full": False
            },
            {
                "title": "Nature Photography Walk",
                "category": "Outdoor",
                "location": "Botanical Gardens Entrance",
                "date": "28 Mar 2026",
                "time": "9:00 AM - 12:00 PM",
                "description": "Guided walk focusing on capturing the beauty of nature. Tips on composition and lighting.",
                "instructions": "Bring any camera, including smartphone cameras.",
                "quota": 12,
                "is_full": True
            },
            {
                "title": "Community Gardening Day",
                "category": "Outdoor",
                "location": "Urban Garden Plot 4",
                "date": "05 Apr 2026",
                "time": "8:30 AM - 11:30 AM",
                "description": "Join us for planting seasonal vegetables and maintaining our shared garden beds.",
                "instructions": "Gardening gloves and tools provided. Water provided.",
                "quota": 20,
                "is_full": False
            },

            # Volunteer
            {
                "title": "Food Bank Sorting",
                "category": "Volunteer",
                "location": "City Food Bank Warehouse",
                "date": "14 Mar 2026",
                "time": "1:00 PM - 4:00 PM",
                "description": "Help sort and pack non-perishable food items for distribution to families in need.",
                "instructions": "Closed-toe shoes required. Light lifting involved.",
                "quota": 15,
                "is_full": True
            },
            {
                "title": "Reading Buddies at Primary School",
                "category": "Volunteer",
                "location": "Northside Primary Library",
                "date": "24 Mar 2026",
                "time": "10:00 AM - 11:30 AM",
                "description": "Read stories to young children and help foster a love for books.",
                "instructions": "Background check required (forms provided on arrival).",
                "quota": 10,
                "is_full": False
            },
            {
                "title": "Hospital Visitor Program",
                "category": "Volunteer",
                "location": "General Hospital Lobby",
                "date": "30 Mar 2026",
                "time": "2:00 PM - 4:00 PM",
                "description": "Spend time chatting with patients who may be lonely or need company.",
                "instructions": "Orientation provided before the session.",
                "quota": 8,
                "is_full": True
            }
        ]

        # 3. Insert Activities
        creator = User.query.filter_by(username='dummy_user_20').first()
        if not creator:
            creator = dummy_users[-1] # fallback
        print(f"Using {creator.username} as activity creator.")

        for item in activities_data:
            # Check if exists to avoid dupes on re-run
            exists = Activity.query.filter_by(title=item['title'], date=item['date']).first()
            if exists:
                print(f"Activity '{item['title']}' already exists. Skipping.")
                activity = exists
            else:
                activity = Activity(
                    title=item['title'],
                    category=item['category'],
                    location=item['location'],
                    date=item['date'],
                    time=item['time'],
                    description=item['description'],
                    instructions=item['instructions'],
                    quota=item['quota'],
                    creator_id=creator.id,
                    image=images.get(item['category'], "https://loremflickr.com/800/400/activity")
                )
                db.session.add(activity)
                db.session.commit()
                print(f"Created Activity: {item['title']}")

            # 4. Handle "Is Full" Logic
            # Verify current participant count
            current_count = activity.get_participant_count()
            
            if item['is_full']:
                needed = item['quota'] - current_count
                if needed > 0:
                    print(f"  - Marking as FULL. Adding {needed} participants...")
                    # Take random users from dummy list
                    # We need enough unique users. 
                    available_users = [u for u in dummy_users if not activity.has_user_joined(u.id)]
                    
                    to_add = available_users[:needed]
                    for u in to_add:
                        p = ActivityParticipant(activity_id=activity.id, user_id=u.id)
                        db.session.add(p)
                    
                    try:
                        db.session.commit()
                        print(f"  - Added {len(to_add)} participants.")
                    except Exception as e:
                        db.session.rollback()
                        print(f"  - Error adding participants: {e}")
            else:
                # Add a random few just so it's not empty (e.g. 2-5)
                if current_count == 0:
                    count_to_add = random.randint(2, min(5, activity.quota - 1))
                    print(f"  - Adding {count_to_add} random participants for realism...")
                    available_users = [u for u in dummy_users if not activity.has_user_joined(u.id)]
                    to_add = available_users[:count_to_add]
                    for u in to_add:
                        p = ActivityParticipant(activity_id=activity.id, user_id=u.id)
                        db.session.add(p)
                    db.session.commit()

        print("Seeding complete!")

if __name__ == "__main__":
    seed()
