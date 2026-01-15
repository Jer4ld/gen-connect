"""
GenConnect - Social Network Web Application
Main Application File (app.py)
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import or_, and_
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///genconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)


# ==================== MODELS ====================

class User(db.Model):
    """User model for authentication and profile management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    interests = db.Column(db.String(255), nullable=True)
    profile_picture = db.Column(db.String(255), default='default.jpg')
    banner_image = db.Column(db.String(255), default='default_banner.jpg')
    member_type = db.Column(db.String(50), default='Youth Member')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    
    # Follow relationships
    followers = db.relationship(
        'Follow',
        foreign_keys='Follow.followed_id',
        backref='followed_user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    following = db.relationship(
        'Follow',
        foreign_keys='Follow.follower_id',
        backref='follower_user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Community memberships
    community_memberships = db.relationship('CommunityMember', backref='user', lazy=True, cascade='all, delete-orphan')
    
    # Messaging relationships
    sent_messages = db.relationship(
        'Message',
        foreign_keys='Message.sender_id',
        backref='sender',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    received_messages = db.relationship(
        'Message',
        foreign_keys='Message.receiver_id',
        backref='receiver',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Contacts
    contacts_initiated = db.relationship(
        'Contact',
        foreign_keys='Contact.user_id',
        backref='user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    contacts_received = db.relationship(
        'Contact',
        foreign_keys='Contact.contact_user_id',
        backref='contact_user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify user password"""
        return check_password_hash(self.password_hash, password)
    
    def get_follower_count(self):
        """Get number of followers"""
        return Follow.query.filter_by(followed_id=self.id).count()
    
    def get_following_count(self):
        """Get number of users being followed"""
        return Follow.query.filter_by(follower_id=self.id).count()
    
    def get_post_count(self):
        """Get number of posts"""
        return Post.query.filter_by(user_id=self.id).count()
    
    def get_contacts(self):
        """Get all accepted contacts for this user"""
        contacts = Contact.query.filter(
            or_(
                and_(Contact.user_id == self.id, Contact.status == 'accepted'),
                and_(Contact.contact_user_id == self.id, Contact.status == 'accepted')
            )
        ).all()
        
        contact_users = []
        for contact in contacts:
            if contact.user_id == self.id:
                contact_users.append(contact.contact_user)
            else:
                contact_users.append(contact.user)
        
        return contact_users
    
    def get_unread_message_count(self):
        """Get count of unread messages"""
        return Message.query.filter_by(receiver_id=self.id, is_read=False).count()
    
    def __repr__(self):
        return f'<User {self.username}>'


class Post(db.Model):
    """Post model for user content"""
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    
    def get_like_count(self):
        """Get number of likes"""
        return Like.query.filter_by(post_id=self.id).count()
    
    def get_comment_count(self):
        """Get number of comments"""
        return Comment.query.filter_by(post_id=self.id).count()
    
    def __repr__(self):
        return f'<Post {self.id}>'


class Comment(db.Model):
    """Comment model for post interactions"""
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Comment {self.id}>'


class Like(db.Model):
    """Like model for post reactions"""
    __tablename__ = 'likes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)
    
    def __repr__(self):
        return f'<Like {self.id}>'


class Follow(db.Model):
    """Follow model for user relationships"""
    __tablename__ = 'follows'
    
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('follower_id', 'followed_id', name='unique_follow'),)
    
    def __repr__(self):
        return f'<Follow {self.follower_id} -> {self.followed_id}>'


class Community(db.Model):
    """Community model for group interactions"""
    __tablename__ = 'communities'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    memberships = db.relationship('CommunityMember', backref='community', lazy=True, cascade='all, delete-orphan')
    
    def get_member_count(self):
        """Get number of community members"""
        return CommunityMember.query.filter_by(community_id=self.id).count()
    
    def __repr__(self):
        return f'<Community {self.name}>'


class CommunityMember(db.Model):
    """CommunityMember model for user-community relationships"""
    __tablename__ = 'community_members'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'community_id', name='unique_membership'),)
    
    def __repr__(self):
        return f'<CommunityMember {self.user_id} in {self.community_id}>'


class Message(db.Model):
    """Message model for direct messaging between users"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def mark_as_read(self):
        """Mark message as read"""
        self.is_read = True
        db.session.commit()
    
    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} to {self.receiver_id}>'


class Contact(db.Model):
    """Contact model for managing user connections"""
    __tablename__ = 'contacts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    contact_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, blocked
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'contact_user_id', name='unique_contact'),)
    
    def accept(self):
        """Accept contact request"""
        self.status = 'accepted'
        db.session.commit()
    
    def block(self):
        """Block contact"""
        self.status = 'blocked'
        db.session.commit()
    
    def __repr__(self):
        return f'<Contact {self.user_id} -> {self.contact_user_id} ({self.status})>'


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Landing page"""
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        email = request.form.get('email')
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
    """Handle user registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('signup'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


@app.route('/home')
def home():
    """Home feed"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    posts = Post.query.order_by(Post.created_at.desc()).all()
    current_user = User.query.get_or_404(session['user_id'])
    
    return render_template('home.html', posts=posts, current_user=current_user)


@app.route('/profile')
@app.route('/profile/<username>')
def profile(username=None):
    """User profile page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if username:
        user = User.query.filter_by(username=username).first_or_404()
    else:
        user = User.query.get_or_404(session['user_id'])
    
    communities = Community.query.join(CommunityMember).filter(
        CommunityMember.user_id == user.id
    ).all()
    
    return render_template('profile.html', user=user, communities=communities,
                         is_own_profile=(user.id == session['user_id']))


@app.route('/messages')
def messages():
    """Messages page - list of conversations"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get_or_404(session['user_id'])
    contacts = current_user.get_contacts()
    
    # Get last message with each contact
    conversations = []
    for contact in contacts:
        last_message = Message.query.filter(
            or_(
                and_(Message.sender_id == current_user.id, Message.receiver_id == contact.id),
                and_(Message.sender_id == contact.id, Message.receiver_id == current_user.id)
            )
        ).order_by(Message.created_at.desc()).first()
        
        unread_count = Message.query.filter_by(
            sender_id=contact.id,
            receiver_id=current_user.id,
            is_read=False
        ).count()
        
        conversations.append({
            'contact': contact,
            'last_message': last_message,
            'unread_count': unread_count
        })
    
    # Sort by last message time
    conversations.sort(key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min, reverse=True)
    
    return render_template('messages.html', conversations=conversations, current_user=current_user)


@app.route('/messages/<int:contact_id>')
def message_thread(contact_id):
    """View message thread with a specific contact"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get_or_404(session['user_id'])
    contact = User.query.get_or_404(contact_id)
    
    # Get all messages between users
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user.id, Message.receiver_id == contact.id),
            and_(Message.sender_id == contact.id, Message.receiver_id == current_user.id)
        )
    ).order_by(Message.created_at.asc()).all()
    
    # Mark messages as read
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.mark_as_read()
    
    contacts = current_user.get_contacts()
    
    return render_template('message_thread.html', 
                         contact=contact, 
                         messages=messages,
                         contacts=contacts,
                         current_user=current_user)


@app.route('/send_message', methods=['POST'])
def send_message():
    """Send a new message"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    
    if not content or not receiver_id:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    # Check if users are contacts
    contact = Contact.query.filter(
        or_(
            and_(Contact.user_id == session['user_id'], Contact.contact_user_id == receiver_id),
            and_(Contact.user_id == receiver_id, Contact.contact_user_id == session['user_id'])
        ),
        Contact.status == 'accepted'
    ).first()
    
    if not contact:
        return jsonify({'success': False, 'message': 'Not in contacts'}), 403
    
    new_message = Message(
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        content=content
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    return jsonify({'success': True, 'message_id': new_message.id})


@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    """Delete a message"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    message = Message.query.get_or_404(message_id)
    
    # Only sender can delete
    if message.sender_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    db.session.delete(message)
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/edit_message/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    """Edit a message"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    message = Message.query.get_or_404(message_id)
    
    # Only sender can edit
    if message.sender_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    new_content = request.form.get('content')
    if not new_content:
        return jsonify({'success': False, 'message': 'Content required'}), 400
    
    message.content = new_content
    message.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/add_contact', methods=['POST'])
def add_contact():
    """Add a new contact by email"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    email = request.form.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
    
    contact_user = User.query.filter_by(email=email).first()
    
    if not contact_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if contact_user.id == session['user_id']:
        return jsonify({'success': False, 'message': 'Cannot add yourself'}), 400
    
    # Check if contact already exists
    existing = Contact.query.filter(
        or_(
            and_(Contact.user_id == session['user_id'], Contact.contact_user_id == contact_user.id),
            and_(Contact.user_id == contact_user.id, Contact.contact_user_id == session['user_id'])
        )
    ).first()
    
    if existing:
        return jsonify({'success': False, 'message': 'Contact already exists'}), 400
    
    new_contact = Contact(
        user_id=session['user_id'],
        contact_user_id=contact_user.id,
        status='accepted'  # Auto-accept for now
    )
    
    db.session.add(new_contact)
    db.session.commit()
    
    flash(f'Added {contact_user.username} to your contacts!', 'success')
    return jsonify({'success': True, 'contact_id': contact_user.id})


@app.route('/remove_contact/<int:contact_id>', methods=['POST'])
def remove_contact(contact_id):
    """Remove a contact"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    contact = Contact.query.filter(
        or_(
            and_(Contact.user_id == session['user_id'], Contact.contact_user_id == contact_id),
            and_(Contact.user_id == contact_id, Contact.contact_user_id == session['user_id'])
        )
    ).first_or_404()
    
    db.session.delete(contact)
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/create_post', methods=['POST'])
def create_post():
    """Create a new post"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    image_url = request.form.get('image_url')
    
    if content:
        new_post = Post(
            content=content,
            image_url=image_url,
            user_id=session['user_id']
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', 'success')
    else:
        flash('Post content cannot be empty', 'error')
    
    return redirect(url_for('home'))


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return '<h1>404 - Page Not Found</h1><p>The page you are looking for does not exist.</p>', 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return '<h1>500 - Internal Server Error</h1><p>Something went wrong on our end.</p>', 500


# ==================== INITIALIZATION ====================

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        db.drop_all()
        db.create_all()
        
        print("Database tables created!")
        
        # Create sample users
        users_data = [
            {'username': 'demo_user', 'email': 'demo@genconnect.com', 'password': 'demo1234'},
            {'username': 'Qien', 'email': 'qien@genconnect.com', 'password': 'demo1234'},
            {'username': 'Thant', 'email': 'thant@genconnect.com', 'password': 'demo1234'},
            {'username': 'Nabeel', 'email': 'nabeel@genconnect.com', 'password': 'demo1234'},
            {'username': 'Jerald', 'email': 'jerald@genconnect.com', 'password': 'demo1234'}
        ]
        
        created_users = []
        for user_data in users_data:
            user = User(username=user_data['username'], email=user_data['email'])
            user.set_password(user_data['password'])
            db.session.add(user)
            created_users.append(user)
        
        db.session.commit()
        
        # Create contacts between users
        contacts_data = [
            (1, 2), (1, 3), (1, 4), (1, 5)
        ]
        
        for user_id, contact_id in contacts_data:
            contact = Contact(user_id=user_id, contact_user_id=contact_id, status='accepted')
            db.session.add(contact)
        
        db.session.commit()
        
        # Create sample communities and memberships
        communities_data = [
            {'name': 'The Digital Ethics Forum', 'description': 'Discussing moral challenges'},
            {'name': 'Budgeting & Beyond', 'description': 'Financial wisdom'},
            {'name': 'The Green Thumb Collective', 'description': 'Gardening tips'}
        ]
        
        for comm_data in communities_data:
            community = Community(**comm_data)
            db.session.add(community)
        
        db.session.commit()
        
        print("Sample data created!")
        print("Demo accounts:")
        for user in created_users:
            print(f"  - Email: {user.email}, Password: demo1234")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
