
from app import app, db, Activity

def check_db():
    with app.app_context():
        activities = Activity.query.limit(5).all()
        for a in activities:
            print(f"ID: {a.id} | Title: {a.title} | Image: {a.image}")

if __name__ == "__main__":
    check_db()
