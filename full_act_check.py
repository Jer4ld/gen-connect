import json
from app import app, db, Activity, User, ActivityParticipant

with app.app_context():
    data = {
        "users": [u.username for u in User.query.all()],
        "user_ids": {u.username: u.id for u in User.query.all()},
        "activities": []
    }
    
    for a in Activity.query.all():
        data["activities"].append({
            "id": a.id,
            "title": a.title,
            "creator_id": a.creator_id,
            "creator_username": User.query.get(a.creator_id).username if User.query.get(a.creator_id) else "Unknown"
        })
    
    with open("full_act_check.json", "w") as f:
        json.dump(data, f, indent=4)
    print("Full check dumped to full_act_check.json")
