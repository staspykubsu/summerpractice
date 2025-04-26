from app import app
from models import db, User, TaskList, Task, SharedList

def setup_db():
    with app.app_context():
        # Создаем все таблицы
        db.drop_all()
        db.create_all()
        
        print("Database tables created successfully.")

if __name__ == '__main__':
    setup_db()