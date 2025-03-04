from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

# Database setup


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(app, model_class=Base)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model


class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(
        Integer, autoincrement=True, primary_key=True)
    email: Mapped[str] = mapped_column(
        String(250), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(250), nullable=False)

# Todo Model


class Todo(db.Model):
    id: Mapped[int] = mapped_column(
        Integer, autoincrement=True, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey('user.id'), nullable=False)
    task: Mapped[str] = mapped_column(String(250), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow)

# Create tables


def create_tables():
    with app.app_context():
        db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Page


@app.route('/')
def home():
    return render_template("index.html")

# Login


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid credentials!", "danger")

    return render_template("login.html")

# Signup


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]
        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=8)

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))

        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

# Dashboard - Protected


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        task = request.form["task"]
        new_task = Todo(user_id=current_user.id, task=task)
        db.session.add(new_task)
        db.session.commit()
        flash("Task added!", "success")

    tasks = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", tasks=tasks)

# Delete Task


@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Todo.query.get(task_id)
    if task and task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        flash("Task deleted!", "success")

    return redirect(url_for("dashboard"))

# Logout


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
