from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    task_lists = db.relationship('TaskList', backref='owner', lazy=True)
    shared_lists = db.relationship('SharedList', backref='user', lazy=True)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

class TaskList(db.Model):
    __tablename__ = 'task_lists'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    secret_key = db.Column(db.String(50), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    tasks = db.relationship('Task', backref='task_list', lazy=True)
    shared_with = db.relationship('SharedList', backref='task_list', lazy=True)

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed
    duration = db.Column(db.Integer)  # in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    task_list_id = db.Column(db.Integer, db.ForeignKey('task_lists.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    user = db.relationship('User', backref='tasks')

class SharedList(db.Model):
    __tablename__ = 'shared_lists'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_list_id = db.Column(db.Integer, db.ForeignKey('task_lists.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)