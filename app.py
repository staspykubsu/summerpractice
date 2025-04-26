from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
from models import User, TaskList, Task, SharedList, db as models_db
models_db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Личный кабинет
@app.route('/dashboard')
@login_required
def dashboard():
    user_task_lists = TaskList.query.filter_by(user_id=current_user.id).all()
    shared_lists = SharedList.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', task_lists=user_task_lists, shared_lists=shared_lists)

# Создание списка задач
@app.route('/create_task_list', methods=['GET', 'POST'])
@login_required
def create_task_list():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        secret_key = secrets.token_urlsafe(16)
        
        new_task_list = TaskList(
            name=name,
            description=description,
            secret_key=secret_key,
            user_id=current_user.id
        )
        db.session.add(new_task_list)
        db.session.commit()
        
        flash('Task list created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('create_task_list.html')

# Просмотр списка задач
@app.route('/task_list/<int:task_list_id>')
@login_required
def view_task_list(task_list_id):
    task_list = TaskList.query.get_or_404(task_list_id)
    
    # Проверка доступа
    if task_list.user_id != current_user.id:
        shared = SharedList.query.filter_by(
            user_id=current_user.id,
            task_list_id=task_list_id
        ).first()
        if not shared:
            flash('You do not have access to this task list', 'error')
            return redirect(url_for('dashboard'))
    
    tasks = Task.query.filter_by(task_list_id=task_list_id).all()
    return render_template('task_list.html', task_list=task_list, tasks=tasks)

# Создание задачи
@app.route('/task_list/<int:task_list_id>/create_task', methods=['GET', 'POST'])
@login_required
def create_task(task_list_id):
    task_list = TaskList.query.get_or_404(task_list_id)
    
    # Проверка доступа
    if task_list.user_id != current_user.id:
        flash('You can only create tasks in your own lists', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']
        duration = int(request.form['duration']) if request.form['duration'] else None
        
        new_task = Task(
            title=title,
            description=description,
            status=status,
            duration=duration,
            task_list_id=task_list_id,
            user_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        
        flash('Task created successfully!', 'success')
        return redirect(url_for('view_task_list', task_list_id=task_list_id))
    
    return render_template('create_task.html', task_list=task_list)

# Редактирование задачи
@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = db.session.query(Task).get(task_id)
    
    if not task:
        flash('Task not found', 'error')
        return redirect(url_for('dashboard'))

    # Проверка владельца задачи
    if task.user_id != current_user.id:
        flash('You can only edit your own tasks', 'error')
        return redirect(url_for('view_task_list', task_list_id=task.task_list_id))
    
    if request.method == 'POST':
        try:
            # Получаем данные из формы
            task.title = request.form.get('title', task.title)
            task.description = request.form.get('description', task.description)
            task.status = request.form.get('status', task.status)
            duration = request.form.get('duration')
            task.duration = int(duration) if duration else None
            
            # Явно отмечаем объект как измененный
            db.session.add(task)
            
            # Проверяем, есть ли изменения
            if db.session.is_modified(task):
                db.session.commit()
                flash('Task updated successfully!', 'success')
            else:
                flash('No changes were made', 'info')
            
            return redirect(url_for('view_task_list', task_list_id=task.task_list_id))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating task: {str(e)}', 'error')
            app.logger.error(f"Error updating task: {str(e)}")
    
    return render_template('edit_task.html', task=task)

# Удаление задачи
@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    try:
        # Получаем задачу в текущей сессии
        task = db.session.query(Task).get(task_id)
        
        if not task:
            flash('Task not found', 'error')
            return redirect(url_for('dashboard'))

        # Проверка владельца задачи
        if task.user_id != current_user.id:
            flash('You can only delete your own tasks', 'error')
            return redirect(url_for('view_task_list', task_list_id=task.task_list_id))
        
        # Получаем task_list_id перед удалением
        task_list_id = task.task_list_id
        
        # Удаляем задачу
        db.session.delete(task)
        db.session.commit()
        
        flash('Task deleted successfully!', 'success')
        return redirect(url_for('view_task_list', task_list_id=task_list_id))
    
    except Exception as e:
        db.session.rollback()
        flash('Error deleting task: ' + str(e), 'error')
        app.logger.error('Error deleting task: %s', str(e))
        return redirect(url_for('dashboard'))

# Совместный доступ к списку задач
@app.route('/share_task_list', methods=['GET', 'POST'])
@login_required
def share_task_list():
    if request.method == 'POST':
        secret_key = request.form['secret_key']
        
        task_list = TaskList.query.filter_by(secret_key=secret_key).first()
        if not task_list:
            flash('Invalid secret key', 'error')
            return redirect(url_for('share_task_list'))
        
        # Проверка, что пользователь не владелец
        if task_list.user_id == current_user.id:
            flash('You are the owner of this task list', 'error')
            return redirect(url_for('share_task_list'))
        
        # Проверка, что доступ уже не предоставлен
        existing_share = SharedList.query.filter_by(
            user_id=current_user.id,
            task_list_id=task_list.id
        ).first()
        
        if existing_share:
            flash('You already have access to this task list', 'error')
            return redirect(url_for('share_task_list'))
        
        new_share = SharedList(
            user_id=current_user.id,
            task_list_id=task_list.id
        )
        db.session.add(new_share)
        db.session.commit()
        
        flash('Access granted to the task list!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('share_list.html')

# Профиль пользователя
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Редактирование профиля
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        try:
            # Получаем текущего пользователя в рамках текущей сессии
            user = db.session.query(User).get(current_user.id)
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('profile'))

            new_username = request.form.get('username', '').strip()
            new_email = request.form.get('email', '').strip()
            new_password = request.form.get('new_password', '').strip()

            # Проверяем изменения username
            if new_username and new_username != user.username:
                if User.query.filter(User.username == new_username, User.id != user.id).first():
                    flash('This username is already taken', 'error')
                    return redirect(url_for('edit_profile'))
                user.username = new_username

            # Проверяем изменения email
            if new_email and new_email != user.email:
                if User.query.filter(User.email == new_email, User.id != user.id).first():
                    flash('This email is already registered', 'error')
                    return redirect(url_for('edit_profile'))
                user.email = new_email

            # Обновляем пароль, если указан
            if new_password:
                user.password = generate_password_hash(new_password, method='sha256')

            # Явно добавляем пользователя в сессию
            db.session.add(user)
            
            # Проверяем, есть ли изменения
            if db.session.is_modified(user):
                db.session.commit()
                flash('Profile updated successfully!', 'success')
                # Обновляем данные в Flask-Login
                login_user(user)
            else:
                flash('No changes were made', 'info')

            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
            app.logger.error(f"Error updating profile: {str(e)}")
            return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html')

if __name__ == '__main__':
    app.run(debug=True)