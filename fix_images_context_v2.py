
from app import app, db, Activity
import random

def get_image_url(title, category):
    title_lower = title.lower()
    keywords = "activity"
    
    # Even more specific mappings
    if "abstract painting" in title_lower: keywords = "abstract,painting,canvas"
    elif "knitting" in title_lower: keywords = "knitting,wool,yarn"
    elif "cooking" in title_lower or "pasta" in title_lower: keywords = "cooking,chef,pasta"
    elif "email" in title_lower or "web" in title_lower: keywords = "laptop,typing"
    elif "smartphone security" in title_lower: keywords = "smartphone,security,lock"
    elif "video calling" in title_lower: keywords = "tablet,video,call"
    elif "tai chi" in title_lower: keywords = "tai-chi,park,exercise"
    elif "photography" in title_lower: keywords = "camera,nature,photography"
    elif "gardening" in title_lower: keywords = "garden,plants,flowers"
    elif "food bank" in title_lower: keywords = "food,charity,box"
    elif "reading buddies" in title_lower: keywords = "reading,children,library"
    elif "hospital" in title_lower: keywords = "hospital,patient,care"
    elif "pottery" in title_lower: keywords = "pottery,clay,ceramics"
    elif "chess" in title_lower: keywords = "chess,strategy,boardgame"
    elif "smart home" in title_lower: keywords = "smarthome,alexa,gadget"
    elif "phishing" in title_lower: keywords = "email,scam,warning"
    elif "sunset yoga" in title_lower: keywords = "yoga,sunset,beach"
    elif "bird watching" in title_lower: keywords = "bird,binoculars,nature"
    elif "soup kitchen" in title_lower: keywords = "kitchen,serving,soup"
    elif "beach cleanup" in title_lower: keywords = "beach,trash,ocean"
    else:
        # Fallback to category defaults with variety
        if category == "Hobbies": keywords = "hobby,creative"
        elif category == "Tech Help": keywords = "tech,code"
        elif category == "Outdoor": keywords = "nature,adventure"
        elif category == "Volunteer": keywords = "helping,community"

    # Use a large random range to bypass any caching
    random_id = random.randint(1001, 99999)
    # Different service attempt for "cooking" to ensure it looks different if needed?
    # No, loremflickr is usually fine if keywords are specific.
    return f"https://loremflickr.com/800/400/{keywords}?random={random_id}"

def fix_images_context_v2():
    with app.app_context():
        print("Starting Refined Image Refresh...")
        activities = Activity.query.all()
        count = 0
        
        for activity in activities:
            new_url = get_image_url(activity.title, activity.category)
            activity.image = new_url
            count += 1
            print(f"Refreshed '{activity.title}' -> {new_url}")

        try:
            db.session.commit()
            print(f"Successfully updated {count} activities.")
        except Exception as e:
            db.session.rollback()
            print(f"Error during commit: {e}")

if __name__ == "__main__":
    fix_images_context_v2()
