from app import app, db, Activity, User
import os

with app.app_context():
    # Target user (johntan@username)
    target_user = User.query.get(1)
    if not target_user:
        print("Target user 1 not found!")
    else:
        print(f"Re-assigning activities to {target_user.username} (ID: 1)")
        
        # Find activities created by dummy_user_20 (ID 33) or others that should be 'mine'
        # We'll just take all activities created by ID 33
        acts = Activity.query.filter_by(creator_id=33).all()
        for a in acts:
            a.creator_id = 1
            print(f"  - Re-assigned: {a.title}")
        
        # Also check for creator 999
        acts_999 = Activity.query.filter_by(creator_id=999).all()
        for a in acts_999:
            a.creator_id = 1
            print(f"  - Re-assigned: {a.title}")

        db.session.commit()
        print("Done!")
