from app import app, User
with app.app_context():
    users = User.query.all()
    for u in users:
        print(f"ID: {u.id}, Username: {u.username}")
