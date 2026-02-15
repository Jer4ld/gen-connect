from app import app, db, Activity, User
import random
import os

with app.app_context():
    print(f"Using DB at: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # johntan@username is ID 1
    main_user_id = 1
    
    # Dummy users are IDs 14 to 33
    dummy_users = User.query.filter(User.username.like('dummy_user_%')).all()
    dummy_user_ids = [u.id for u in dummy_users]
    
    if not dummy_user_ids:
        print("Error: No dummy users found!")
        # Fallback to hardcoded IDs if query fails for some reason
        dummy_user_ids = list(range(14, 34))

    # Get all activities currently assigned to main user
    # excluding "Football" (ID 1)
    activities_to_move = Activity.query.filter(
        Activity.creator_id == main_user_id,
        Activity.id != 1
    ).all()
    
    print(f"Found {len(activities_to_move)} activities assigned to user 1 (excluding Football).")
    
    for act in activities_to_move:
        if act.title == "Artistic Reminder Test" or "Reminder Test" in act.title:
            print(f"Deleting test activity: {act.title} (ID {act.id})")
            db.session.delete(act)
        else:
            new_creator_id = random.choice(dummy_user_ids)
            print(f"Moving '{act.title}' (ID {act.id}) to user {new_creator_id}")
            act.creator_id = new_creator_id
            
    db.session.commit()
    print("Database committed.")
    
    # Verify immediately
    remaining = Activity.query.filter(Activity.creator_id == 1).all()
    print(f"Activities remaining for user 1: {[a.title for a in remaining]}")
