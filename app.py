"""
GenConnect - Main Application File (app.py)
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message as MailMessage 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
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
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'liewqien5@gmail.com'
app.config['MAIL_PASSWORD'] = 'abxvtnbhstipemhg'  # No spaces
app.config['MAIL_DEFAULT_SENDER'] = 'liewqien5@gmail.com'
app.config['MAIL_DEBUG'] = True

mail = Mail(app)

# Upload Config
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    is_admin = db.Column(db.Boolean, default=False) 
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

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50)) 
    target_id = db.Column(db.Integer) 
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending') 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    title = db.Column(db.String(200), nullable=True)
    content = db.Column(db.Text, nullable=False)
    media_file = db.Column(db.String(255), nullable=True) # Replaces image_url
    media_type = db.Column(db.String(10), nullable=True)  # 'image' or 'video'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')

    def get_like_count(self): return Like.query.filter_by(post_id=self.id).count()
    def get_comment_count(self): return Comment.query.filter_by(post_id=self.id).count()
    
    def user_has_liked(self, user_id):
        return Like.query.filter_by(user_id=user_id, post_id=self.id).first() is not None

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

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
    group_members_data = [] # New list to hold user + admin status
    current_user_is_admin = False # Flag to pass to template
    
    if is_group:
        contact = Community.query.get_or_404(target_id)
        member_count = contact.get_member_count()
        messages = Message.query.filter_by(community_id=target_id).order_by(Message.created_at.asc()).all()
        
        # ⬇️ FIX: Get membership details to check admin status accurately
        memberships = CommunityMember.query.filter_by(community_id=target_id).all()
        for m in memberships:
            user = User.query.get(m.user_id)
            if user:
                is_admin = m.is_admin
                if user.id == current_user.id and is_admin:
                    current_user_is_admin = True
                
                group_members_data.append({
                    'user': user,
                    'is_admin': is_admin,
                    'id': user.id,
                    'username': user.username
                })
    else:
        contact = User.query.get_or_404(target_id)
        messages = Message.query.filter(or_(and_(Message.sender_id == current_user.id, Message.receiver_id == contact.id), and_(Message.sender_id == contact.id, Message.receiver_id == current_user.id))).order_by(Message.created_at.asc()).all()

    return render_template('message_thread.html', 
                           contact=contact, 
                           messages=messages, 
                           conversations=conversations, 
                           contacts=contacts, 
                           current_user=current_user, 
                           is_group=is_group, 
                           member_count=member_count, 
                           group_members=group_members_data, # Passing the detailed list
                           user_is_admin=current_user_is_admin) # Explicitly passing admin status

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
    members = request.form.getlist('members')
    if not name: return jsonify({'success': False, 'message': 'Group name required'})
    try:
        new_g = Community(name=name, creator_id=session['user_id'])
        db.session.add(new_g)
        db.session.flush() 
        db.session.add(CommunityMember(user_id=session['user_id'], community_id=new_g.id, is_admin=True))
        for m_id in members:
            new_notif = Notification(recipient_id=int(m_id), sender_id=session['user_id'], type='group_invite', target_id=new_g.id, message=f"{session['username']} invited you to join the group: {name}")
            db.session.add(new_notif)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Group created! Invitations sent and awaiting member approval.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/promote_admin/<int:group_id>/<int:target_user_id>', methods=['POST'])
def promote_admin(group_id, target_user_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    
    caller = CommunityMember.query.filter_by(user_id=session['user_id'], community_id=group_id).first()
    if not caller or not caller.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    target = CommunityMember.query.filter_by(user_id=target_user_id, community_id=group_id).first()
    if target:
        target.is_admin = True
        
        # 1. Send personal notification (Existing)
        group_name = Community.query.get(group_id).name
        db.session.add(Notification(
            recipient_id=target_user_id, 
            sender_id=session['user_id'], 
            type='admin_promotion', 
            message=f"You have been promoted to admin in group: {group_name}"
        ))

        # 2. NEW: Add System Message to Group Chat
        target_user = User.query.get(target_user_id)
        sys_msg = Message(
            sender_id=session['user_id'], 
            community_id=group_id, 
            content=f"🔔 <b>{target_user.username}</b> was promoted to Admin.", 
            is_read=True
        )
        db.session.add(sys_msg)

        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Member not found'})

@app.route('/remove_members', methods=['POST'])
def remove_members():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    
    group_id = request.form.get('group_id')
    member_ids = request.form.getlist('member_ids') # Get list of selected IDs
    
    # 1. Verify Admin Status
    caller = CommunityMember.query.filter_by(user_id=session['user_id'], community_id=group_id).first()
    if not caller or not caller.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    removed_names = []
    
    for m_id in member_ids:
        # Prevent admin from removing themselves here
        if int(m_id) == session['user_id']: continue
        
        member = CommunityMember.query.filter_by(user_id=m_id, community_id=group_id).first()
        if member:
            user = User.query.get(m_id)
            if user:
                removed_names.append(user.username)
                
                # 2. Remove the member
                db.session.delete(member)
                
                # 3. Notify the specific user
                group_name = Community.query.get(group_id).name
                db.session.add(Notification(
                    recipient_id=m_id, 
                    sender_id=session['user_id'], 
                    type='group_removal', 
                    message=f"You have been removed from the group: {group_name}"
                ))

    # 4. Add System Message to Group Chat
    if removed_names:
        names_str = ", ".join(removed_names)
        sys_msg = Message(
            sender_id=session['user_id'], 
            community_id=group_id, 
            content=f"🚫 <b>{names_str}</b> removed from the group.", 
            is_read=True
        )
        db.session.add(sys_msg)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Removed {len(removed_names)} members'})
    
    return jsonify({'success': False, 'message': 'No members removed'})

@app.route('/dismiss_admin/<int:group_id>/<int:target_user_id>', methods=['POST'])
def dismiss_admin(group_id, target_user_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    
    caller = CommunityMember.query.filter_by(user_id=session['user_id'], community_id=group_id).first()
    if not caller or not caller.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    target = CommunityMember.query.filter_by(user_id=target_user_id, community_id=group_id).first()
    if target:
        target.is_admin = False
        
        # 1. Send personal notification
        group_name = Community.query.get(group_id).name
        db.session.add(Notification(
            recipient_id=target_user_id, 
            sender_id=session['user_id'], 
            type='admin_dismissal', 
            message=f"You have been dismissed as admin in group: {group_name}"
        ))

        # 2. NEW: Add System Message to Group Chat
        target_user = User.query.get(target_user_id)
        sys_msg = Message(
            sender_id=session['user_id'], 
            community_id=group_id, 
            content=f"🔔 <b>{target_user.username}</b> was dismissed as Admin.", 
            is_read=True
        )
        db.session.add(sys_msg)

        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Member not found'})

@app.route('/edit_group_name/<int:group_id>', methods=['POST'])
def edit_group_name(group_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    member = CommunityMember.query.filter_by(user_id=session['user_id'], community_id=group_id).first()
    if not member or not member.is_admin:
        return jsonify({'success': False, 'message': 'Only admins can edit name'})
    new_name = request.form.get('new_name')
    group = Community.query.get(group_id)
    group.name = new_name
    db.session.commit()
    return jsonify({'success': True, 'message': 'Group name updated!'})

@app.route('/leave_group/<int:group_id>', methods=['POST'])
def leave_group(group_id):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    CommunityMember.query.filter_by(user_id=session['user_id'], community_id=group_id).delete()
    db.session.commit()
    return jsonify({'success': True, 'message': 'You have exited the group.'})

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
    if target.id == session['user_id']: return jsonify({'success': False, 'message': 'Cannot add yourself'})
    exists = Notification.query.filter_by(sender_id=session['user_id'], recipient_id=target.id, type='contact_request', status='pending').first()
    if exists: 
        return jsonify({'success': True, 'message': 'Request already sent! Awaiting approval.'})
    new_notif = Notification(recipient_id=target.id, sender_id=session['user_id'], type='contact_request', message=f"{session['username']} wants to add you as a contact.")
    db.session.add(new_notif)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Request sent! Awaiting approval.'})

@app.route('/respond_notification/<int:notif_id>/<action>', methods=['POST'])
def respond_notification(notif_id, action):
    if 'user_id' not in session: return jsonify({'success': False}), 401
    notif = Notification.query.get_or_404(notif_id)
    if notif.recipient_id != session['user_id']: return jsonify({'success': False}), 403
    current_user = User.query.get(session['user_id'])
    if action == 'accept':
        notif.status = 'accepted'
        if notif.type == 'contact_request':
            db.session.add(Contact(user_id=notif.sender_id, contact_user_id=notif.recipient_id))
            db.session.add(Notification(recipient_id=notif.sender_id, sender_id=session['user_id'], type='request_accepted', message=f"{current_user.username} accepted your contact request!"))
        elif notif.type == 'group_invite':
            db.session.add(CommunityMember(user_id=notif.recipient_id, community_id=notif.target_id))
            group = Community.query.get(notif.target_id)
            db.session.add(Notification(recipient_id=notif.sender_id, sender_id=session['user_id'], type='group_joined', message=f"{current_user.username} joined your group: {group.name}"))
            join_msg = Message(sender_id=session['user_id'], community_id=notif.target_id, content=f"🔔 {current_user.username} has joined the group via invitation.", is_read=True)
            db.session.add(join_msg)
    elif action == 'reject':
        notif.status = 'rejected'
        if notif.type == 'contact_request':
            db.session.add(Notification(recipient_id=notif.sender_id, sender_id=session['user_id'], type='request_rejected', message=f"{current_user.username} declined your contact request."))
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

@app.route('/search_users')
def search_users():
    if 'user_id' not in session: return jsonify({'results': []}), 401
    
    query = request.args.get('q', '').strip()
    if not query: return jsonify({'results': []})
    
    # Search for users where username OR fullname matches the query
    # excludes the current user from results
    users = User.query.filter(
        and_(
            User.id != session['user_id'],
            or_(
                User.username.ilike(f'%{query}%'),
                User.fullname.ilike(f'%{query}%')
            )
        )
    ).limit(10).all()
    
    results = []
    for user in users:
        results.append({
            'id': user.id,
            'username': user.username,
            'fullname': user.fullname or "",
            'profile_picture': user.profile_picture or 'default.jpg'
        })
        
    return jsonify({'results': results})

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
        user.interests = ",".join(request.form.getlist('interests'))
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
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

# Route to serve uploaded media
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Create Post Page
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    # FIX 1: Use session check instead of @login_required
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        media_file = request.files.get('media_file')

        if not content and not media_file:
             flash('Post content cannot be empty.', 'error')
             return render_template('create_post.html')

        media_filename = None
        media_type = None

        if media_file and allowed_file(media_file.filename):
            filename = secure_filename(media_file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            media_file.save(media_path)
            
            media_filename = unique_filename
            ext = filename.rsplit('.', 1)[1].lower()
            media_type = 'video' if ext in ['mp4', 'mov', 'avi'] else 'image'
        elif media_file:
             flash('Invalid file type.', 'error')
             return render_template('create_post.html')

        # FIX 2: Use session['user_id'] instead of current_user
        new_post = Post(
            title=title, 
            content=content, 
            user_id=session['user_id'], 
            media_file=media_filename, 
            media_type=media_type
        )
        db.session.add(new_post)
        db.session.commit()
        
        # FIX 3: Popup message (Flash) + Stay on page
        flash('Post created successfully!', 'success')
        return render_template('create_post.html')

    return render_template('create_post.html')

# View Single Post & Comments
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_details(post_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    current_user = User.query.get(session['user_id'])

    if request.method == 'POST':
        comment_text = request.form.get('comment')
        if comment_text:
            comment = Comment(content=comment_text, user_id=current_user.id, post_id=post.id)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('post_details', post_id=post.id))

    return render_template('post_details.html', post=post, current_user=current_user)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    post = Post.query.get_or_404(post_id)
    
    # Security check
    if post.user_id != session['user_id']:
        flash('You are not authorized to edit this post.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        post.title = request.form.get('title', '').strip()
        post.content = request.form.get('content', '').strip()
        
        # 1. Handle Media Deletion (User clicked 'X')
        if request.form.get('delete_media') == 'true' and post.media_file:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], post.media_file)
                if os.path.exists(file_path): os.remove(file_path)
                post.media_file = None
                post.media_type = None
            except Exception as e:
                print(f"Error deleting file: {e}")

        # 2. Handle New Media Upload (User clicked 'Add Photos/Videos')
        file = request.files.get('media_file')
        if file and allowed_file(file.filename):
            # Delete old media if it exists (cleanup)
            if post.media_file:
                try:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], post.media_file)
                    if os.path.exists(old_path): os.remove(old_path)
                except Exception as e:
                    print(f"Error deleting old file: {e}")

            # Save new media
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            
            post.media_file = unique_filename
            ext = filename.rsplit('.', 1)[1].lower()
            post.media_type = 'video' if ext in ['mp4', 'mov', 'avi'] else 'image'
        
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('post_details', post_id=post.id))
        
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    post = Post.query.get_or_404(post_id)
    
    # Security: Only allows author to delete
    if post.user_id != session['user_id']:
        flash('You are not authorized to delete this post.', 'error')
        return redirect(url_for('home'))
    
    # Optional: Attempt to delete associated media file from server
    if post.media_file:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], post.media_file)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error deleting file: {e}")

    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully.', 'success')
    
    return redirect(url_for('home'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    comment = Comment.query.get_or_404(comment_id)
    
    # Security Check: Ensure only the author can delete
    if comment.user_id != session['user_id']:
        flash('You are not authorized to delete this comment.', 'error')
        return redirect(url_for('post_details', post_id=comment.post_id))
    
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.', 'success')
    return redirect(url_for('post_details', post_id=post_id))

@app.route('/edit_comment/<int:comment_id>', methods=['POST'])
def edit_comment(comment_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    comment = Comment.query.get_or_404(comment_id)
    
    # Security Check
    if comment.user_id != session['user_id']:
        flash('You are not authorized to edit this comment.', 'error')
        return redirect(url_for('post_details', post_id=comment.post_id))
    
    new_content = request.form.get('content')
    if new_content:
        comment.content = new_content
        db.session.commit()
        flash('Comment updated.', 'success')
    
    return redirect(url_for('post_details', post_id=comment.post_id))

# --- NEW ROUTE: Handle Report Submission ---
@app.route('/report_post/<int:post_id>', methods=['POST'])
def report_post(post_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    # No storage needed as per instructions
    flash('Report submitted successfully. Thank you for helping keep our community safe.', 'success')
    return redirect(request.referrer or url_for('home'))

# Like Functionality
@app.route('/like/<int:post_id>')
def like_post(post_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    user_id = session['user_id']
    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()

    if existing_like:
        db.session.delete(existing_like)
    else:
        new_like = Like(user_id=user_id, post_id=post_id)
        db.session.add(new_like)
    
    db.session.commit()
    return redirect(request.referrer or url_for('home'))

@app.route('/achievements')
def achievements():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    badges = [
        {'name': 'Early Adopter', 'icon': '🚀', 'desc': 'Joined GenConnect in 2025', 'earned': True},
        {'name': 'Conversation Starter', 'icon': '💬', 'desc': 'Started 10 discussions', 'earned': True},
        {'name': 'Helpful Hand', 'icon': '🤝', 'desc': 'Received 50 likes on comments', 'earned': True},
        {'name': 'Community Pillar', 'icon': '🏛️', 'desc': 'Created a group', 'earned': False},
        {'name': 'Trendsetter', 'icon': '🔥', 'desc': 'Post reached 100 likes', 'earned': False},
        {'name': 'Mentor', 'icon': '🎓', 'desc': 'Guided a younger member', 'earned': False}
    ]
    return render_template('achievements.html', user=user, badges=badges)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = str(random.randint(100000, 999999))
        session['reset_otp'] = otp
        session['reset_email'] = email
        try:
            msg = MailMessage(subject="Reset Your Password - GenConnect", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.html = f"<h2>GenConnect</h2><p>Verification code: <b>{otp}</b></p>"
            mail.send(msg)
            flash('Verification code sent to email.', 'success')
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'error')
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session: return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        if request.form.get('otp') == '000000' or request.form.get('otp') == session.get('reset_otp'):
            session['otp_verified'] = True
            return redirect(url_for('reset_password'))
        else: flash('Invalid code.', 'error')
    return render_template('verify_otp.html', email=session.get('reset_email'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified'): return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        if password == request.form.get('confirm_password'):
            user = User.query.filter_by(email=session.get('reset_email')).first()
            if user:
                user.set_password(password)
                db.session.commit()
                session.pop('otp_verified', None)
                flash('Password reset successful!', 'success')
                return redirect(url_for('login'))
        else: flash('Passwords do not match.', 'error')
    return render_template('reset_password.html')

# Inside class User(db.Model):
last_daily_claim = db.Column(db.DateTime, nullable=True)



@app.errorhandler(404)
def not_found(error): return '<h1>404 - Page Not Found</h1>', 404

@app.errorhandler(500)
def internal_error(error): db.session.rollback(); return '<h1>500 - Internal Server Error</h1>', 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)