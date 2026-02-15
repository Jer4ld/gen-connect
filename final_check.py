from app import app, db, Activity, ActivityParticipant
import json

with app.app_context():
    user_id = 1
    created = Activity.query.filter_by(creator_id=user_id).all()
    joined_entries = ActivityParticipant.query.filter_by(user_id=user_id).all()
    joined_acts = Activity.query.filter(Activity.id.in_([e.activity_id for e in joined_entries])).all() if joined_entries else []
    
    print(f"Created for User {user_id}: {[a.title for a in created]}")
    print(f"Joined for User {user_id}: {[a.title for a in joined_acts]}")
