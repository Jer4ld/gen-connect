from app import app, db, User, Activity
from flask import url_for
import uuid

def test_creation_flow():
    with app.test_client() as client:
        # Create a temp user
        rand_id = str(uuid.uuid4())[:8]
        uname = f'testuser_{rand_id}'
        email = f'{uname}@example.com'
        
        with app.app_context():
            user = User(username=uname, email=email)
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
            print(f"Created temp user: {uname}, Email: {email}")

        # 1. Login (using email as per app.py)
        print("Logging in...")
        res = client.post('/login', data={'email': email, 'password': 'password123'}, follow_redirects=True)
        if b'Logout' not in res.data:
            print("Login failed")
            # print(res.data.decode()[:1000])
            return
        
        # 2. Post to create activity
        print("Creating activity...")
        form_data = {
            'title': 'Test Verification Activity',
            'category': 'Hobbies',
            'location': 'Verification Lab',
            'date': '2026-04-10',
            'time': '10:00 AM - 12:00 PM',
            'description': 'Automated verification desc.',
            'instructions': 'None',
            'quota': '15'
        }
        res = client.post('/activities/create', data=form_data, follow_redirects=False)
        
        # 3. Check redirect
        location = res.headers.get('Location', '')
        print(f"Redirect Location: {location}")
        
        if '/created' in location:
            print("SUCCESS: Redirected to confirmation page.")
            
            # Follow redirect
            res = client.get(location)
            if b'Activity Created Successfully!' in res.data and b'Test Verification Activity' in res.data:
                print("SUCCESS: Confirmation page displays correct data.")
            else:
                print("FAILURE: Confirmation page missing data.")
                # print(res.data.decode())
        else:
            print("FAILURE: Did not redirect correctly.")
            # print(res.data.decode())

        # Cleanup
        with app.app_context():
            # Delete by email to be sure
            User.query.filter_by(email=email).delete()
            # Delete activity by title
            Activity.query.filter_by(title='Test Verification Activity').delete()
            db.session.commit()
            print("Cleanup complete.")

if __name__ == "__main__":
    test_creation_flow()
