from app import app, db, Activity, User
import random

with app.app_context():
    # johntan@username is ID 1
    main_user_id = 1
    
    # Dummy users are IDs 14 to 33
    dummy_user_ids = list(range(14, 34))
    
    # Get all activities currently or previously assigned to main user
    # excluding "Football" (ID 1)
    activities_to_move = Activity.query.filter(
        Activity.creator_id == main_user_id,
        Activity.id != 1
    ).all()
    
    print(f"Found {len(activities_to_move)} activities to move.")
    
    for act in activities_to_move:
        if act.title == "Artistic Reminder Test":
            print(f"Deleting test activity: {act.title} (ID {act.id})")
            db.session.delete(act)
        else:
            new_creator_id = random.choice(dummy_user_ids)
            old_creator_id = act.creator_id
            act.creator_id = new_creator_id
            print(f"Moved '{act.title}' (ID {act.id}) from {old_creator_id} to {new_creator_id}")
            
    db.session.commit()
    print("Re-distribution complete.")
