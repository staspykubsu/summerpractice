import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost/task_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False