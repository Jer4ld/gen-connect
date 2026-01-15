"""
GenConnect - Social Network Web Application
Main Application File (app.py)
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
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
    
    # Relationships - using strings to avoid circular imports
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
    
    # Ensure unique likes per user per post
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
    
    # Ensure unique follow relationships
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
    
    # Ensure unique memberships
    __table_args__ = (db.UniqueConstraint('user_id', 'community_id', name='unique_membership'),)
    
    def __repr__(self):
        return f'<CommunityMember {self.user_id} in {self.community_id}>'


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Landing page - shows feed if logged in, otherwise login page"""
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
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('signup'))
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


@app.route('/home')
def home():
    """Home feed - requires authentication"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get all posts for feed
    posts = Post.query.order_by(Post.created_at.desc()).all()
    current_user = User.query.get(session['user_id'])
    
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
        user = User.query.get(session['user_id'])
    
    # Get user's communities
    communities = Community.query.join(CommunityMember).filter(
        CommunityMember.user_id == user.id
    ).all()
    
    return render_template('profile.html', user=user, communities=communities,
                         is_own_profile=(user.id == session['user_id']))


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
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('500.html'), 500


# ==================== INITIALIZATION ====================

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        # Drop all tables and recreate (for development only)
        db.drop_all()
        db.create_all()
        
        print("Database tables created!")
        
        # Create sample user
        sample_user = User(
            username='demo_user',
            email='demo@genconnect.com',
            bio='University student pursuing computer science. Fascinated by old technologies and life before the internet.',
            interests='Coding, Vintage Gaming, Future Trends, Personal Finance/gardening, fishing',
            member_type='Youth Member'
        )
        sample_user.set_password('demo123')
        db.session.add(sample_user)
        
        # Create sample communities
        communities_data = [
            {
                'name': 'The Digital Ethics Forum',
                'description': 'Discussing the moral challenges and societal impact of new technology with experienced perspectives',
                'image_url': 'digital_ethics.jpg'
            },
            {
                'name': 'Budgeting & Beyond',
                'description': 'Practical wisdom from seniors on saving, investing, and achieving long-term financial security',
                'image_url': 'budgeting.jpg'
            },
            {
                'name': 'The Green Thumb Collective',
                'description': 'Sharing intergenerational tips on planting, growing, and urban farming, yours post modern, space-saving garden projects',
                'image_url': 'green_thumb.jpg'
            }
        ]
        
        for comm_data in communities_data:
            community = Community(**comm_data)
            db.session.add(community)
        
        db.session.commit()
        
        # Add user to communities
        for i in range(1, 4):
            membership = CommunityMember(user_id=sample_user.id, community_id=i)
            db.session.add(membership)
        
        # Create sample posts
        sample_posts = [
            {
                'content': 'Just joined GenConnect! Excited to connect with people across generations.',
                'user_id': sample_user.id
            },
            {
                'content': 'What are your favorite vintage technologies? I love old computers and early video games!',
                'user_id': sample_user.id
            }
        ]
        
        for post_data in sample_posts:
            post = Post(**post_data)
            db.session.add(post)
        
        db.session.commit()
        print("Sample data created!")
        print("Demo account - Email: demo@genconnect.com, Password: demo123")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)