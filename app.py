from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, FileField, SelectField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import qrcode
import cv2
import os
from pyzbar.pyzbar import decode
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(50), nullable=False, unique=True)
    qr_code = db.Column(db.String(200), nullable=False)
    attendance_records = db.relationship('Attendance', backref='student', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    actual_time = db.Column(db.Time, nullable=False)

class GenerateQRForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    student_id = StringField('Student ID', validators=[DataRequired()])

class ScanQRForm(FlaskForm):
    file = FileField('Select QR Code', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher'), ('admin', 'Admin')], validators=[DataRequired()])

@app.route('/')
def home():
    if 'username' in session:
        role = session['role']
        if role == 'student':
            return redirect(url_for('student_attendance'))
        elif role == 'teacher':
            return redirect(url_for('teacher_attendance'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        flash('Invalid username or password!', 'error')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/student_attendance')
def student_attendance():
    if 'username' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    return render_template('student_attendance.html')

@app.route('/teacher_attendance')
def teacher_attendance():
    if 'username' not in session or session['role'] != 'teacher':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    return render_template('teacher_attendance.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    students = Student.query.all()
    attendance_records = Attendance.query.all()
    return render_template('admin_dashboard.html', students=students, attendance_records=attendance_records)

def save_qr_code(student_id, qr_data):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    file_path = f"static/uploads/{student_id}.png"
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    img.save(file_path)
    return file_path

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    form = GenerateQRForm()
    if form.validate_on_submit():
        name = form.name.data
        student_id = form.student_id.data
        qr_data = f"Name: {name}, Student ID: {student_id}, Timestamp: {datetime.now()}"
        file_path = save_qr_code(student_id, qr_data)

        try:
            new_student = Student(name=name, student_id=student_id, qr_code=file_path)
            db.session.add(new_student)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Student ID already exists!', 'error')
            return redirect(url_for('student_attendance'))

        return render_template('qr_preview.html', qr_code=student_id, name=name)
    flash('Invalid input data!', 'error')
    return redirect(url_for('student_attendance'))

@app.route('/scan', methods=['POST'])
def scan_qr():
    form = ScanQRForm()
    if form.validate_on_submit():
        file = form.file.data
        file_path = os.path.join('static/uploads', file.filename)
        file.save(file_path)

        img = cv2.imread(file_path)
        decoded_objects = decode(img)
        if not decoded_objects:
            flash('No QR code found in the image!', 'error')
            return redirect(url_for('student_attendance'))

        for obj in decoded_objects:
            data = obj.data.decode('utf-8')
            student_id = extract_student_id(data)
            if student_id:
                student = Student.query.filter_by(student_id=student_id).first()
                if student:
                    attendance = Attendance(student_id=student.id, actual_time=datetime.now().time())
                    db.session.add(attendance)
                    db.session.commit()
                    flash(f'Scanned Data: {data}', 'success')
                else:
                    flash('Student not found in the database!', 'error')
            else:
                flash('Invalid QR code data!', 'error')

        return redirect(url_for('student_attendance'))
    flash('Invalid input data!', 'error')
    return redirect(url_for('student_attendance'))

def extract_student_id(data):
    student_info = data.split(', ')
    for info in student_info:
        if info.startswith('Student ID:'):
            return info.split(': ')[1]
    return None

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
