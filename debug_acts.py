from app import app, db, Activity, User
import json

with app.app_context():
    all_acts = Activity.query.all()
    acts_data = []
    for act in all_acts:
        acts_data.append({
            "id": act.id,
            "title": act.title,
            "creator_id": act.creator_id,
            "created_at": act.created_at.isoformat() if act.created_at else None,
            "category": act.category
        })
    
    with open('debug_acts.json', 'w') as f:
        json.dump(acts_data, f, indent=4)
    
    print(f"Total Activities: {len(all_acts)}")
    print(f"User 1 Created: {len([a for a in all_acts if a.creator_id == 1])}")
