from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, FileField
from wtforms.validators import DataRequired
import qrcode
import cv2
import os
from pyzbar.pyzbar import decode
from datetime import datetime
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(50), nullable=False, unique=True)
    qr_code = db.Column(db.String(200), nullable=False)

class GenerateQRForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    student_id = StringField('Student ID', validators=[DataRequired()])

class ScanQRForm(FlaskForm):
    file = FileField('Select QR Code', validators=[DataRequired()])

@app.route('/')
def index():
    generate_form = GenerateQRForm()
    scan_form = ScanQRForm()
    return render_template('index.html', generate_form=generate_form, scan_form=scan_form)

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
            return redirect(url_for('index'))

        return render_template('qr_preview.html', qr_code=student_id, name=name)
    flash('Invalid input data!', 'error')
    return redirect(url_for('index'))

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
            return redirect(url_for('index'))

        for obj in decoded_objects:
            data = obj.data.decode('utf-8')
            student_id = extract_student_id(data)
            if student_id:
                student = Student.query.filter_by(student_id=student_id).first()
                if student:
                    flash(f'Scanned Data: {data}', 'success')
                else:
                    flash('Student not found in the database!', 'error')
            else:
                flash('Invalid QR code data!', 'error')

        return redirect(url_for('index'))
    flash('Invalid input data!', 'error')
    return redirect(url_for('index'))

def extract_student_id(data):
    student_info = data.split(', ')
    for info in student_info:
        if info.startswith('Student ID:'):
            return info.split(': ')[1]
    return None

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
