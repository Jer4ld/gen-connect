from app import app, db, User, Activity
from flask import url_for

def test_creation_flow():
    with app.test_client() as client:
        # 1. Login dummy_user_1
        print("Logging in...")
        res = client.post('/login', data={'username': 'dummy_user_1', 'password': 'password123'}, follow_redirects=True)
        if b'Logout' not in res.data:
            print("Login failed")
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
        
        # Looking for something like /activities/25/created (or whatever the ID is)
        if '/created' in location:
            print("SUCCESS: Redirected to confirmation page.")
            
            # Follow redirect
            res = client.get(location)
            if b'Activity Created Successfully!' in res.data and b'Test Verification Activity' in res.data:
                print("SUCCESS: Confirmation page displays correct data.")
            else:
                print("FAILURE: Confirmation page missing success text or activity title.")
                # print(res.data.decode()[:500]) # debug
        else:
            print("FAILURE: Did not redirect to confirmation page.")
            # print(res.data.decode()[:500]) # debug

if __name__ == "__main__":
    with app.app_context():
        test_creation_flow()
