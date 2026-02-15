import json
from app import app, db, Activity, User, ActivityParticipant
import os

with app.app_context():
    data = {
        "users": [],
        "activities": [],
        "participants": []
    }
    
    users = User.query.all()
    for u in users:
        data["users"].append({"id": u.id, "username": u.username, "email": u.email})

    acts = Activity.query.all()
    for a in acts:
        data["activities"].append({
            "id": a.id, 
            "title": a.title, 
            "creator_id": a.creator_id,
            "date": a.date
        })

    parts = ActivityParticipant.query.all()
    for p in parts:
        data["participants"].append({
            "user_id": p.user_id,
            "activity_id": p.activity_id
        })

    with open("db_dump.json", "w") as f:
        json.dump(data, f, indent=4)
    print("Dumped to db_dump.json")
