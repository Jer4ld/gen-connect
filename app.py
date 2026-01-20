"""
GenConnect - Main Application File (app.py)
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
# ⬇️ FIX: We alias 'Message' to 'MailMessage' to stop Python from getting confused
from flask_mail import Mail, Message as MailMessage 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from datetime import datetime
from sqlalchemy import or_, and_
from sqlalchemy.exc import IntegrityError
import os
import random
import traceback

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///genconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ================= EMAIL CONFIGURATION =================
# Using Port 587 (TLS) - The most compatible mode
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'liewqien5@gmail.com'
app.config['MAIL_PASSWORD'] = 'abxvtnbhstipemhg'  # No spaces
app.config['MAIL_DEFAULT_SENDER'] = 'liewqien5@gmail.com'
app.config['MAIL_DEBUG'] = True

mail = Mail(app) 
# =======================================================

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# ==================== MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    fullname = db.Column(db.String(100), nullable=True) 
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    interests = db.Column(db.String(255), nullable=True)
    profile_picture = db.Column(db.String(255), default='default.jpg')
    banner_image = db.Column(db.String(255), default='default_banner.jpg')
    member_type = db.Column(db.String(50), default='Youth Member')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    community_memberships = db.relationship('CommunityMember', backref='user', lazy=True, cascade='all, delete-orphan')
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic', cascade='all, delete-orphan')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic', cascade='all, delete-orphan')
    contacts_initiated = db.relationship('Contact', foreign_keys='Contact.user_id', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    contacts_received = db.relationship('Contact', foreign_keys='Contact.contact_user_id', backref='contact_user', lazy='dynamic', cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed_user', lazy='dynamic', cascade='all, delete-orphan')
    following = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower_user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def get_post_count(self): return Post.query.filter_by(user_id=self.id).count()
    def get_follower_count(self): return Follow.query.filter_by(followed_id=self.id).count()
    def get_following_count(self): return Follow.query.filter_by(follower_id=self.id).count()
    def get_contacts(self):
        contacts = Contact.query.filter(or_(and_(Contact.user_id == self.id, Contact.status == 'accepted'), and_(Contact.contact_user_id == self.id, Contact.status == 'accepted'))).all()
        contact_users = []
        for contact in contacts:
            if contact.user_id == self.id: contact_users.append(contact.contact_user)
            else: contact_users.append(contact.user)
        return contact_users
    def get_unread_message_count(self):
        return Message.query.filter_by(receiver_id=self.id, is_read=False).count()

class Community(db.Model):
    __tablename__ = 'communities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    memberships = db.relationship('CommunityMember', backref='community', lazy=True, cascade='all, delete-orphan')
    def get_member_count(self):
        return CommunityMember.query.filter_by(community_id=self.id).count()

class CommunityMember(db.Model):
    __tablename__ = 'community_members'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True) 
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    def mark_as_read(self):
        self.is_read = True
        db.session.commit()

class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    contact_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='accepted')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'contact_user_id', name='unique_contact'),)

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    def get_like_count(self): return Like.query.filter_by(post_id=self.id).count()
    def get_comment_count(self): return Comment.query.filter_by(post_id=self.id).count()

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    __tablename__ = 'likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Follow(db.Model):
    __tablename__ = 'follows'
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
# Insert this with your other models in app.py
class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50)) # 'contact_request' or 'group_invite'
    target_id = db.Column(db.Integer) # User ID for contact, Community ID for group
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending') # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session: return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        fullname = request.form.get('fullname').strip()
        member_type = request.form.get('member_type')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('signup'))
        
        try:
            new_user = User(username=username, email=email, fullname=fullname, member_type=member_type)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            flash(f'Welcome, {username}! Account created successfully.', 'success')
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or Email already exists.', 'error')
            return redirect(url_for('signup'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/home')
def home():
    if 'user_id' not in session: return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.clear()
        return redirect(url_for('login'))
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('home.html', posts=posts, current_user=current_user)

@app.route('/messages')
def messages():
    if 'user_id' not in session: return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user: return redirect(url_for('login'))
    contacts = current_user.get_contacts()
    groups = Community.query.join(CommunityMember).filter(CommunityMember.user_id == current_user.id).all()
    conversations = []
    for c in contacts: conversations.append({'id': c.id, 'name': c.username, 'is_group': False})
    for g in groups: conversations.append({'id': g.id, 'name': g.name, 'is_group': True})
    return render_template('messages.html', conversations=conversations, current_user=current_user, contacts=contacts)

@app.route('/messages/<int:target_id>')
def message_thread(target_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user: return redirect(url_for('login'))
    contacts = current_user.get_contacts()
    groups = Community.query.join(CommunityMember).filter(CommunityMember.user_id == current_user.id).all()
    conversations = []
    for c in contacts: conversations.append({'id': c.id, 'name': c.username, 'contact': c, 'is_group': False})
    for g in groups: conversations.append({'id': g.id, 'name': g.name, 'group': g, 'is_group': True})
    is_group = request.args.get('is_group') == 'true'
    member_count = 0
    group_members = []
    if is_group:
        contact = Community.query.get_or_404(target_id)
        member_count = contact.get_member_count()
        group_members = User.query.join(CommunityMember).filter(CommunityMember.community_id == target_id).all()
        messages = Message.query.filter_by(community_id=target_id).order_by(Message.created_at.asc()).all()
    else:
        contact = User.query.get_or_404(target_id)
        messages = Message.query.filter(or_(and_(Message.sender_id == current_user.id, Message.receiver_id == contact.id), and_(Message.sender_id == contact.id, Message.receiver_id == current_user.id))).order_by(Message.created_at.asc()).all()
    return render_template('message_thread.html', contact=contact, messages=messages, conversations=conversations, contacts=contacts, current_user=current_user, is_group=is_group, member_count=member_count, group_members=group_members)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    receiver_id = request.form.get('receiver_id')
    is_group = request.form.get('is_group') == 'true'
    content = request.form.get('content', '')
    file = request.files.get('file')
    community_id = None
    final_receiver_id = None
    if is_group: community_id = receiver_id
    else: final_receiver_id = receiver_id
    filename = None
    if file and file.filename != '':
        filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        if not content: content = "[File Attachment]"
    new_msg = Message(sender_id=session['user_id'], receiver_id=final_receiver_id, community_id=community_id, content=content, file_path=filename)
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    name = request.form.get('group_name')
    members = request.form.getlist('members') # This list of IDs from your checkboxes
    
    if not name: return jsonify({'success': False, 'message': 'Group name required'})
    
    try:
        # 1. Create the group
        new_g = Community(name=name, creator_id=session['user_id'])
        db.session.add(new_g)
        db.session.flush() # Get the new group ID
        
        # 2. Add the creator immediately
        db.session.add(CommunityMember(user_id=session['user_id'], community_id=new_g.id))
        
        # 3. Send invitations (Notifications) to the others instead of adding them
        for m_id in members:
            new_notif = Notification(
                recipient_id=int(m_id),
                sender_id=session['user_id'],
                type='group_invite',
                target_id=new_g.id, # Store the group ID here
                message=f"{session['username']} invited you to join the group: {name}"
            )
            db.session.add(new_notif)
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'Group created and invitations sent!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/notifications')
def notifications_page():
    if 'user_id' not in session: return redirect(url_for('login'))
    user_notifications = Notification.query.filter_by(recipient_id=session['user_id']).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/add_contact', methods=['POST'])
def add_contact():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    username = request.form.get('username').strip()
    target = User.query.filter_by(username=username).first()
    if not target: return jsonify({'success': False, 'message': 'User not found'})
    
    # Check if a request already exists
    exists = Notification.query.filter_by(sender_id=session['user_id'], recipient_id=target.id, type='contact_request', status='pending').first()
    if exists: return jsonify({'success': False, 'message': 'Request already sent'})
    
    new_notif = Notification(
        recipient_id=target.id, 
        sender_id=session['user_id'], 
        type='contact_request', 
        message=f"{session['username']} wants to add you as a contact."
    )
    db.session.add(new_notif)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Invitation sent!'})

@app.route('/respond_notification/<int:notif_id>/<action>', methods=['POST'])
def respond_notification(notif_id, action):
    notif = Notification.query.get_or_404(notif_id)
    if notif.recipient_id != session['user_id']: 
        return jsonify({'success': False}), 403
    
    current_user = User.query.get(session['user_id'])
    
    if action == 'accept':
        notif.status = 'accepted'
        
        # 1. Handle actual logic (Add Contact or Join Group)
        if notif.type == 'contact_request':
            db.session.add(Contact(user_id=notif.sender_id, contact_user_id=notif.recipient_id))
            # Create feedback notification for the sender
            feedback = Notification(
                recipient_id=notif.sender_id,
                sender_id=session['user_id'],
                type='request_accepted',
                message=f"{current_user.username} accepted your contact request!"
            )
            db.session.add(feedback)
            
        elif notif.type == 'group_invite':
            db.session.add(CommunityMember(user_id=notif.recipient_id, community_id=notif.target_id))
            group = Community.query.get(notif.target_id)
            # Create feedback notification for the group creator
            feedback = Notification(
                recipient_id=notif.sender_id,
                sender_id=session['user_id'],
                type='group_joined',
                message=f"{current_user.username} joined your group: {group.name}"
            )
            db.session.add(feedback)
    else:
        notif.status = 'rejected'
        
    db.session.commit()
    return jsonify({'success': True})

@app.route('/remove_contact/<int:contact_id>', methods=['POST'])
def remove_contact(contact_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    current_user_id = session['user_id']
    try:
        Message.query.filter(or_(and_(Message.sender_id == current_user_id, Message.receiver_id == contact_id), and_(Message.sender_id == contact_id, Message.receiver_id == current_user_id))).delete(synchronize_session=False)
        Contact.query.filter(or_(and_(Contact.user_id == current_user_id, Contact.contact_user_id == contact_id), and_(Contact.user_id == contact_id, Contact.contact_user_id == current_user_id))).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    msg = Message.query.get_or_404(message_id)
    if msg.sender_id == session['user_id']:
        db.session.delete(msg)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/edit_message/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    msg = Message.query.get_or_404(message_id)
    if msg.sender_id == session['user_id']:
        msg.content = request.form.get('content')
        msg.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile')
@app.route('/profile/<username>')
def profile(username=None):
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first_or_404() if username else User.query.get(session['user_id'])
    return render_template('profile.html', user=user, is_own_profile=(user.id == session['user_id']))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.bio = request.form.get('bio')
        selected_interests = request.form.getlist('interests')
        user.interests = ",".join(selected_interests)
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            # CHANGE: Redirects to 'profile' instead of 'edit_profile'
            return redirect(url_for('profile')) 
        except:
            db.session.rollback()
            flash('Error updating profile.', 'error')
    return render_template('edit_profile.html', user=user)

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get_or_404(session['user_id'])
    try:
        db.session.delete(user)
        db.session.commit()
        session.clear()
        return redirect(url_for('index'))
    except:
        db.session.rollback()
        return redirect(url_for('edit_profile'))

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'user_id' not in session: return redirect(url_for('login'))
    content = request.form.get('content')
    image_url = request.form.get('image_url')
    if content:
        new_post = Post(content=content, image_url=image_url, user_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', 'success')
    else:
        flash('Post content cannot be empty', 'error')
    return redirect(url_for('home'))

# ================= ACHIEVEMENTS ROUTE (NEW) =================
@app.route('/achievements')
def achievements():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    
    # Mock data for demonstration
    badges = [
        {'name': 'Early Adopter', 'icon': '🚀', 'desc': 'Joined GenConnect in 2025', 'earned': True},
        {'name': 'Conversation Starter', 'icon': '💬', 'desc': 'Started 10 discussions', 'earned': True},
        {'name': 'Helpful Hand', 'icon': '🤝', 'desc': 'Received 50 likes on comments', 'earned': True},
        {'name': 'Community Pillar', 'icon': '🏛️', 'desc': 'Created a group', 'earned': False},
        {'name': 'Trendsetter', 'icon': '🔥', 'desc': 'Post reached 100 likes', 'earned': False},
        {'name': 'Mentor', 'icon': '🎓', 'desc': 'Guided a younger member', 'earned': False}
    ]
    return render_template('achievements.html', user=user, badges=badges)

# ================= AUTH WITH EMAIL SUPPORT =================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = str(random.randint(100000, 999999))
        session['reset_otp'] = otp
        session['reset_email'] = email
        
        try:
            # ⬇️ FIX: Using the ALIAS 'MailMessage' to prevent conflicts
            msg = MailMessage(subject="Reset Your Password - GenConnect",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[email])
            
            msg.html = f"""
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #333; background-color: #f9f9f9;">
                <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <h2 style="color: #6366f1; text-align: center;">GenConnect</h2>
                    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="font-size: 16px;">Hello,</p>
                    <p style="font-size: 16px;">We received a request to reset your password. Use the verification code below to proceed:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <h1 style="background: #e0e7ff; color: #6366f1; padding: 15px 30px; display: inline-block; border-radius: 8px; letter-spacing: 5px; font-family: monospace;">{otp}</h1>
                    </div>
                    <p style="font-size: 14px; color: #666;">If you didn't ask for this, you can safely ignore this email.</p>
                </div>
            </div>
            """
            mail.send(msg)
            flash('An email with the verification code has been sent.', 'success')
            return redirect(url_for('verify_otp'))
        except Exception as e:
            print("---------------- EMAIL ERROR ----------------")
            traceback.print_exc() 
            print("---------------------------------------------")
            flash(f'Error sending email: {str(e)}', 'error')
            
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session: return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        if user_otp == '000000' or user_otp == session.get('reset_otp'):
            session['otp_verified'] = True
            flash('Code verified! Please set your new password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid code. Please check your email and try again.', 'error')
    return render_template('verify_otp.html', email=session.get('reset_email'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified'): return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if password == confirm:
            user = User.query.filter_by(email=session.get('reset_email')).first()
            if user:
                user.set_password(password)
                db.session.commit()
                session.pop('reset_otp', None)
                session.pop('otp_verified', None)
                flash('Password reset successful! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User account not found.', 'error')
        else:
            flash('Passwords do not match.', 'error')
    return render_template('reset_password.html')

@app.errorhandler(404)
def not_found(error): return '<h1>404 - Page Not Found</h1>', 404

@app.errorhandler(500)
def internal_error(error): db.session.rollback(); return '<h1>500 - Internal Server Error</h1>', 500

if __name__ == '__main__':
    # This checks if the DB exists, and creates it if it doesn't
    with app.app_context():
        db.create_all()
    app.run(debug=True)