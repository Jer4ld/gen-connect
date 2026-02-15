from app import app, db, Activity, User, ActivityParticipant
import os

with app.app_context():
    # Check all users first to see who we are
    print("--- Users ---")
    users = User.query.all()
    for u in users:
        print(f"ID: {u.id}, Username: {u.username}")

    print("\n--- Activities ---")
    acts = Activity.query.all()
    for a in acts:
        creator = User.query.get(a.creator_id)
        creator_name = creator.username if creator else "Unknown"
        print(f"ID: {a.id}, Title: {a.title}, CreatorID: {a.creator_id} ({creator_name})")

    print("\n--- Participants ---")
    parts = ActivityParticipant.query.all()
    for p in parts:
        user = User.query.get(p.user_id)
        act = Activity.query.get(p.activity_id)
        print(f"User: {user.username if user else '?'}, Activity: {act.title if act else '?'}")
