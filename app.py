import io
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import os
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hroms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    recovery_password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))

class Applicant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('applicant', uselist=False))
    profile = db.relationship('ApplicantProfile', backref='applicant', uselist=False)
    application_form = db.relationship('ApplicationForm', backref='applicant', uselist=False)

class ApplicantProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    middle_name = db.Column(db.String(50))
    age = db.Column(db.Integer)
    home_address = db.Column(db.String(255))
    state_province = db.Column(db.String(100))
    country_of_origin = db.Column(db.String(100))
    country_of_residence = db.Column(db.String(100))
    profile_picture = db.Column(db.String(255))

class ApplicationForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    title = db.Column(db.String(10))
    date_of_birth = db.Column(db.Date)
    national_insurance_number = db.Column(db.String(20))
    post_code = db.Column(db.String(20))
    nmc_pin = db.Column(db.String(20))
    next_of_kin_full_name = db.Column(db.String(100))
    next_of_kin_relationship = db.Column(db.String(50))
    next_of_kin_phone = db.Column(db.String(20))
    next_of_kin_landline = db.Column(db.String(20))
    next_of_kin_email = db.Column(db.String(120))
    criminal_conviction = db.Column(db.Boolean)
    criminal_conviction_details = db.Column(db.Text)
    signature = db.Column(db.Text)
    consent = db.Column(db.Boolean)
    evidence_stored = db.Column(db.Boolean)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    document_type = db.Column(db.String(50))
    file_path = db.Column(db.String(255))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('staff', uselist=False))
    position = db.Column(db.String(100))
    department = db.Column(db.String(100))
    hire_date = db.Column(db.Date)

class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    staff = db.relationship('Staff', backref='shifts')
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(100))
    role = db.Column(db.String(100))
    status = db.Column(db.String(20), default='scheduled')

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    staff = db.relationship('Staff', backref='attendances')
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.DateTime)
    check_out = db.Column(db.DateTime)
    document = db.Column(db.String(255))

class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    staff = db.relationship('Staff', backref='leaves')
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    leave_type = db.Column(db.String(50))
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    admin_feedback = db.Column(db.Text)

class PaySlip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    staff = db.relationship('Staff', backref='payslips')
    period_start = db.Column(db.Date, nullable=False)
    period_end = db.Column(db.Date, nullable=False)
    basic_salary = db.Column(db.Float, nullable=False)
    overtime_pay = db.Column(db.Float, default=0)
    bonuses = db.Column(db.Float, default=0)
    tax = db.Column(db.Float, default=0)
    insurance = db.Column(db.Float, default=0)
    other_deductions = db.Column(db.Float, default=0)
    gross_pay = db.Column(db.Float, nullable=False)
    net_pay = db.Column(db.Float, nullable=False)
    deductions = db.Column(db.Float, default=0)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    attachment = db.Column(db.String(255))

class Interview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    applicant = db.relationship('Applicant', backref='interviews')
    interview_date = db.Column(db.DateTime, nullable=False)
    details = db.Column(db.Text)
    status = db.Column(db.String(20), default='scheduled')

class OfferLetter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    applicant = db.relationship('Applicant', backref='offer_letters')
    file_path = db.Column(db.String(255))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')

class ROMNCompliance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    signature = db.Column(db.Text)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255))

class PolicyAgreement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    agreement_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255))

class AuditDeclaration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'), nullable=False)
    signature = db.Column(db.Text)
    declaration_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255))

# Decorator functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'staff':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        phone_number = request.form['phone_number']
        recovery_password = request.form['recovery_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists.', 'error')
            return redirect(url_for('signup'))

        new_user = User(
            email=email,
            password=generate_password_hash(password),
            role='applicant',
            phone_number=phone_number,
            recovery_password=generate_password_hash(recovery_password)
        )
        db.session.add(new_user)
        db.session.commit()

        new_applicant = Applicant(user_id=new_user.id)
        db.session.add(new_applicant)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'staff':
                return redirect(url_for('staff_dashboard'))
            else:
                return redirect(url_for('applicant_dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
            app.logger.warning(f"Failed login attempt for email: {email}")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/applicant/dashboard')
@login_required
def applicant_dashboard():
    user = User.query.get(session['user_id'])
    applicant = Applicant.query.filter_by(user_id=user.id).first()
    return render_template('applicant_dashboard.html', user=user, applicant=applicant)

@app.route('/applicant/profile', methods=['GET', 'POST'])
@login_required
def applicant_profile():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        if not applicant.profile:
            profile = ApplicantProfile(applicant_id=applicant.id)
            db.session.add(profile)
        else:
            profile = applicant.profile

        profile.first_name = request.form['first_name']
        profile.last_name = request.form['last_name']
        profile.middle_name = request.form['middle_name']
        profile.age = request.form['age']
        profile.home_address = request.form['home_address']
        profile.state_province = request.form['state_province']
        profile.country_of_origin = request.form['country_of_origin']
        profile.country_of_residence = request.form['country_of_residence']

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"profile_{applicant.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile.profile_picture = filename

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('applicant_profile'))

    return render_template('applicant_profile.html', applicant=applicant)

@app.route('/applicant/edit_request', methods=['GET', 'POST'])
@login_required
def edit_request():
    if request.method == 'POST':
        # Process the edit request
        # You can add logic here to store the edit request or notify admin
        flash('Edit request submitted successfully.', 'success')
        return redirect(url_for('applicant_profile'))
    return render_template('edit_request.html')

@app.route('/applicant/document_upload', methods=['GET', 'POST'])
@login_required
def document_upload():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    documents = Document.query.filter_by(applicant_id=applicant.id).all()
    
    if request.method == 'POST':
        document_type = request.form['document_type']
        file = request.files['document']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{document_type}_{applicant.id}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            existing_document = Document.query.filter_by(applicant_id=applicant.id, document_type=document_type).first()
            if existing_document:
                existing_document.file_path = filename
            else:
                new_document = Document(
                    applicant_id=applicant.id,
                    document_type=document_type,
                    file_path=filename
                )
                db.session.add(new_document)
            
            db.session.commit()
            
            flash(f'{document_type.replace("_", " ").title()} uploaded successfully.', 'success')
            return redirect(url_for('document_upload'))
        else:
            flash('Invalid file type.', 'error')
    
    return render_template('document_upload.html', documents=documents)

@app.route('/applicant/application_form', methods=['GET', 'POST'])
@login_required
def application_form():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    if request.method == 'POST':
        if not applicant.application_form:
            form = ApplicationForm(applicant_id=applicant.id)
            db.session.add(form)
        else:
            form = applicant.application_form

        form.title = request.form['title']
        form.first_name = request.form['first_name']
        form.surname = request.form['surname']
        form.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d')
        form.national_insurance_number = request.form.get('national_insurance_number', '')
        form.post_code = request.form['post_code']
        form.home_address = request.form['home_address']
        form.mobile_number = request.form['mobile_number']
        form.email_address = request.form['email_address']
        form.nmc_pin = request.form['nmc_pin']
        form.next_of_kin_full_name = request.form['next_of_kin_full_name']
        form.next_of_kin_relationship = request.form['next_of_kin_relationship']
        form.next_of_kin_phone = request.form['next_of_kin_phone']
        form.next_of_kin_landline = request.form['next_of_kin_landline']
        form.next_of_kin_email = request.form['next_of_kin_email']
        form.criminal_conviction = request.form['criminal_conviction'] == 'yes'
        form.criminal_conviction_details = request.form['criminal_conviction_details']
        form.signature = request.form['signature']
        form.consent = 'consent' in request.form
        form.evidence_stored = 'evidence_stored' in request.form

        db.session.commit()
        flash('Application form submitted successfully.', 'success')
        return redirect(url_for('applicant_dashboard'))

    return render_template('application_form.html', application=applicant.application_form)

@app.route('/applicant/messages')
@login_required
def applicant_messages():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    messages = Message.query.filter_by(recipient_id=session['user_id']).order_by(Message.timestamp.desc()).all()
    return render_template('applicant_messages.html', messages=messages)

@app.route('/applicant/interviews')
@login_required
def applicant_interviews():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    interviews = Interview.query.filter_by(applicant_id=applicant.id).all()
    return render_template('applicant_interviews.html', interviews=interviews)

@app.route('/applicant/update_interview/<int:interview_id>', methods=['POST'])
@login_required
def update_interview(interview_id):
    interview = Interview.query.get_or_404(interview_id)
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    
    if interview.applicant_id != applicant.id:
        flash('You do not have permission to update this interview.', 'error')
        return redirect(url_for('applicant_interviews'))
    
    action = request.form['action']
    feedback = request.form['feedback']
    
    if action == 'accept':
        interview.status = 'accepted'
    elif action == 'reschedule':
        interview.status = 'reschedule_requested'
    elif action == 'reject':
        interview.status = 'rejected'
    
    interview.details += f"\n\nApplicant feedback: {feedback}"
    db.session.commit()
    
    flash('Interview response submitted successfully.', 'success')
    return redirect(url_for('applicant_interviews'))

@app.route('/applicant/offer_letter')
@login_required
def applicant_offer_letter():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    offer_letter = OfferLetter.query.filter_by(applicant_id=applicant.id).first()
    return render_template('applicant_offer_letter.html', applicant=applicant, offer_letter=offer_letter)

@app.route('/download_offer_letter/<int:letter_id>')
@login_required
def download_offer_letter(letter_id):
    offer_letter = OfferLetter.query.get_or_404(letter_id)
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    
    if not applicant or offer_letter.applicant_id != applicant.id:
        flash('You are not authorized to download this offer letter.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    return send_file(offer_letter.file_path, as_attachment=True)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    total_applicants = Applicant.query.count()
    open_applications = ApplicationForm.query.filter_by(status='pending').count()
    scheduled_interviews = Interview.query.filter_by(status='scheduled').count()
    total_staff = Staff.query.count()
    
    application_status = {
        'pending': ApplicationForm.query.filter_by(status='pending').count(),
        'reviewing': ApplicationForm.query.filter_by(status='reviewing').count(),
        'accepted': ApplicationForm.query.filter_by(status='accepted').count(),
        'rejected': ApplicationForm.query.filter_by(status='rejected').count()
    }
    
    # Get attendance data for the last 7 days
    today = datetime.now().date()
    seven_days_ago = today - timedelta(days=7)
    attendance_data = db.session.query(
        Attendance.date,
        db.func.count(Attendance.id).label('present_count')
    ).filter(Attendance.date >= seven_days_ago).group_by(Attendance.date).all()
    
    attendance_dates = [(seven_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(8)]
    attendance_present = [0] * 8
    attendance_absent = [total_staff] * 8
    
    for date, present_count in attendance_data:
        index = (date - seven_days_ago).days
        attendance_present[index] = present_count
        attendance_absent[index] = total_staff - present_count
    
    recent_activities = []  # You can implement a system to track recent activities
    upcoming_interviews = Interview.query.filter(Interview.interview_date > datetime.now()).order_by(Interview.interview_date).limit(5).all()
    
    return render_template('admin_dashboard.html',
                           total_applicants=total_applicants,
                           open_applications=open_applications,
                           scheduled_interviews=scheduled_interviews,
                           total_staff=total_staff,
                           application_status=application_status,
                           attendance_dates=attendance_dates,
                           attendance_present=attendance_present,
                           attendance_absent=attendance_absent,
                           recent_activities=recent_activities,
                           upcoming_interviews=upcoming_interviews)

@app.route('/admin/applications')
@admin_required
def admin_applications():
    applications = ApplicationForm.query.all()
    return render_template('admin_applications.html', applications=applications)

@app.route('/admin/view_application/<int:application_id>')
@admin_required
def view_application(application_id):
    application = ApplicationForm.query.get_or_404(application_id)
    documents = Document.query.filter_by(applicant_id=application.applicant_id).all()
    return render_template('view_application.html', application=application, documents=documents)

@app.route('/admin/interviews')
@admin_required
def admin_interviews():
    interviews = Interview.query.all()
    return render_template('admin_interviews.html', interviews=interviews)

@app.route('/admin/schedule_interview', methods=['GET', 'POST'])
@admin_required
def schedule_interview():
    if request.method == 'POST':
        applicant_id = request.form['user_id']
        interview_date = datetime.strptime(request.form['interview_date'], '%Y-%m-%dT%H:%M')
        details = request.form['details']
        
        new_interview = Interview(
            applicant_id=applicant_id,
            interview_date=interview_date,
            details=details
        )
        db.session.add(new_interview)
        db.session.commit()
        
        flash('Interview scheduled successfully.', 'success')
        return redirect(url_for('admin_interviews'))
    
    applicants = Applicant.query.all()
    return render_template('schedule_interview.html', applicants=applicants)

@app.route('/admin/messages')
@admin_required
def admin_messages():
    messages = Message.query.filter_by(recipient_id=session['user_id']).order_by(Message.timestamp.desc()).all()
    return render_template('admin_messages.html', messages=messages)

@app.route('/admin/send_message', methods=['GET', 'POST'])
@admin_required
def send_message():
    if request.method == 'POST':
        recipient_id = request.form['recipient_id']
        content = request.form['content']
        
        new_message = Message(
            sender_id=session['user_id'],
            recipient_id=recipient_id,
            content=content
        )
        db.session.add(new_message)
        db.session.commit()
        
        flash('Message sent successfully.', 'success')
        return redirect(url_for('admin_messages'))
    
    applicants = Applicant.query.all()
    return render_template('send_message.html', applicants=applicants)

@app.route('/admin/offer_letters')
@admin_required
def admin_offer_letters():
    offer_letters = OfferLetter.query.all()
    return render_template('admin_offer_letters.html', offer_letters=offer_letters)

@app.route('/admin/upload_offer_letter', methods=['GET', 'POST'])
@admin_required
def upload_offer_letter():
    if request.method == 'POST':
        applicant_id = request.form['applicant_id']
        file = request.files['offer_letter']
        
        if file:
            filename = f"offer_letter_{applicant_id}_{file.filename}"
            file.save(os.path.join('static/uploads', filename))
            
            new_offer_letter = OfferLetter(
                applicant_id=applicant_id,
                file_path=filename
            )
            db.session.add(new_offer_letter)
            db.session.commit()
            
            flash('Offer letter uploaded successfully.', 'success')
            return redirect(url_for('admin_offer_letters'))
    
    applicants = Applicant.query.all()
    return render_template('upload_offer_letter.html', applicants=applicants)

@app.route('/admin/staff')
@admin_required
def admin_staff():
    staff = Staff.query.all()
    return render_template('admin_staff.html', staff=staff)

@app.route('/admin/add_staff', methods=['GET', 'POST'])
@admin_required
def add_staff():
    if request.method == 'POST':
        user_id = request.form['user_id']
        position = request.form['position']
        department = request.form['department']
        hire_date = datetime.strptime(request.form['hire_date'], '%Y-%m-%d')
        
        new_staff = Staff(
            user_id=user_id,
            position=position,
            department=department,
            hire_date=hire_date
        )
        db.session.add(new_staff)
        
        user = User.query.get(user_id)
        user.role = 'staff'
        
        db.session.commit()
        
        flash('Staff member added successfully.', 'success')
        return redirect(url_for('admin_staff'))
    
    applicants = Applicant.query.all()
    return render_template('add_staff.html', applicants=applicants)

@app.route('/admin/shifts')
@admin_required
def admin_shifts():
    shifts = Shift.query.all()
    return render_template('admin_shifts.html', shifts=shifts)

@app.route('/admin/assign_shift', methods=['GET', 'POST'])
@admin_required
def assign_shift():
    if request.method == 'POST':
        staff_id = request.form['staff_id']
        start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        location = request.form['location']
        role = request.form['role']
        
        new_shift = Shift(
            staff_id=staff_id,
            start_time=start_time,
            end_time=end_time,
            location=location,
            role=role
        )
        db.session.add(new_shift)
        db.session.commit()
        
        flash('Shift assigned successfully.', 'success')
        return redirect(url_for('admin_shifts'))
    
    staff = Staff.query.all()
    return render_template('assign_shift.html', staff=staff)

@app.route('/admin/attendance')
@admin_required
def admin_attendance():
    attendances = Attendance.query.all()
    all_staff = Staff.query.all()
    return render_template('admin_attendance.html', attendances=attendances, all_staff=all_staff)

@app.route('/admin/edit_attendance/<int:attendance_id>', methods=['GET', 'POST'])
@admin_required
def edit_attendance(attendance_id):
    attendance = Attendance.query.get_or_404(attendance_id)
    
    if request.method == 'POST':
        attendance.check_in = datetime.strptime(request.form['check_in'], '%Y-%m-%dT%H:%M')
        if request.form['check_out']:
            attendance.check_out = datetime.strptime(request.form['check_out'], '%Y-%m-%dT%H:%M')
        else:
            attendance.check_out = None
        
        db.session.commit()
        flash('Attendance record updated successfully.', 'success')
        return redirect(url_for('admin_attendance'))
    
    return render_template('edit_attendance.html', attendance=attendance)

@app.route('/admin/delete_attendance/<int:attendance_id>', methods=['POST'])
@admin_required
def delete_attendance(attendance_id):
    attendance = Attendance.query.get_or_404(attendance_id)
    db.session.delete(attendance)
    db.session.commit()
    flash('Attendance record deleted successfully.', 'success')
    return redirect(url_for('admin_attendance'))

@app.route('/admin/payslips')
@admin_required
def admin_payslips():
    payslips = PaySlip.query.all()
    return render_template('admin_payslips.html', payslips=payslips)

@app.route('/admin/generate_payslip', methods=['GET', 'POST'])
@admin_required
def generate_payslip():
    if request.method == 'POST':
        staff_id = request.form['staff_id']
        period_start = datetime.strptime(request.form['period_start'], '%Y-%m-%d')
        period_end = datetime.strptime(request.form['period_end'], '%Y-%m-%d')
        basic_salary = float(request.form['basic_salary'])
        overtime_pay = float(request.form['overtime_pay'])
        deductions = float(request.form['deductions'])
        gross_pay = basic_salary + overtime_pay
        net_pay = gross_pay - deductions
        
        new_payslip = PaySlip(
            staff_id=staff_id,
            period_start=period_start,
            period_end=period_end,
            basic_salary=basic_salary,
            overtime_pay=overtime_pay,
            deductions=deductions,
            gross_pay=gross_pay,
            net_pay=net_pay
        )
        db.session.add(new_payslip)
        db.session.commit()
        
        flash('Payslip generated successfully.', 'success')
        return redirect(url_for('admin_payslips'))
    
    staff = Staff.query.all()
    return render_template('generate_payslip.html', staff=staff)

@app.route('/admin/edit_payslip/<int:payslip_id>', methods=['GET', 'POST'])
@admin_required
def edit_payslip(payslip_id):
    payslip = PaySlip.query.get_or_404(payslip_id)
    
    if request.method == 'POST':
        payslip.basic_salary = float(request.form['basic_salary'])
        payslip.overtime_pay = float(request.form['overtime_pay'])
        payslip.deductions = float(request.form['deductions'])
        
        payslip.gross_pay = payslip.basic_salary + payslip.overtime_pay
        payslip.net_pay = payslip.gross_pay - payslip.deductions
        
        db.session.commit()
        flash('Payslip updated successfully.', 'success')
        return redirect(url_for('admin_payslips'))
    
    return render_template('edit_payslip.html', payslip=payslip)

@app.route('/staff/dashboard')
@staff_required
def staff_dashboard():
    staff = Staff.query.filter_by(user_id=session['user_id']).first()
    upcoming_shifts = Shift.query.filter_by(staff_id=staff.id).filter(Shift.start_time > datetime.now()).order_by(Shift.start_time).limit(5).all()
    recent_attendance = Attendance.query.filter_by(staff_id=staff.id).order_by(Attendance.date.desc()).limit(5).all()
    latest_payslip = PaySlip.query.filter_by(staff_id=staff.id).order_by(PaySlip.period_end.desc()).first()
    recent_messages = Message.query.filter_by(recipient_id=session['user_id']).order_by(Message.timestamp.desc()).limit(5).all()
    
    return render_template('staff_dashboard.html', 
                           staff=staff, 
                           upcoming_shifts=upcoming_shifts, 
                           recent_attendance=recent_attendance, 
                           latest_payslip=latest_payslip, 
                           recent_messages=recent_messages)

@app.route('/staff/profile')
@staff_required
def staff_profile():
    staff = Staff.query.filter_by(user_id=session['user_id']).first()
    return render_template('staff_profile.html', staff=staff)

@app.route('/staff/attendance', methods=['GET', 'POST'])
@staff_required
def staff_attendance():
    staff = Staff.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        action = request.form['action']
        now = datetime.now()
        today = now.date()
        
        attendance = Attendance.query.filter_by(staff_id=staff.id, date=today).first()
        
        if action == 'check_in':
            if attendance:
                flash('You have already checked in today.', 'error')
            else:
                new_attendance = Attendance(staff_id=staff.id, date=today, check_in=now)
                db.session.add(new_attendance)
                flash('Check-in successful.', 'success')
        
        elif action == 'check_out':
            if attendance:
                if attendance.check_out:
                    flash('You have already checked out today.', 'error')
                else:
                    attendance.check_out = now
                    flash('Check-out successful.', 'success')
            else:
                flash('You need to check in first.', 'error')
        
        if 'document' in request.files:
            file = request.files['document']
            if file.filename != '':
                filename = f"attendance_{staff.id}_{today}_{file.filename}"
                file.save(os.path.join('static/uploads', filename))
                if attendance:
                    attendance.document = filename
        
        db.session.commit()
        return redirect(url_for('staff_attendance'))
    
    attendances = Attendance.query.filter_by(staff_id=staff.id).order_by(Attendance.date.desc()).all()
    return render_template('staff_attendance.html', attendances=attendances)

@app.route('/staff/shifts')
@staff_required
def staff_shifts():
    staff = Staff.query.filter_by(user_id=session['user_id']).first()
    shifts = Shift.query.filter_by(staff_id=staff.id).order_by(Shift.start_time).all()
    return render_template('staff_shifts.html', shifts=shifts)

@app.route('/staff/leave', methods=['GET', 'POST'])
@staff_required
def staff_leave():
    staff = Staff.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'POST':
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        leave_type = request.form['leave_type']
        reason = request.form['reason']
        
        new_leave = Leave(
            staff_id=staff.id,
            start_date=start_date,
            end_date=end_date,
            leave_type=leave_type,
            reason=reason
        )
        db.session.add(new_leave)
        db.session.commit()
        
        flash('Leave request submitted successfully.', 'success')
        return redirect(url_for('staff_leave'))
    
    leaves = Leave.query.filter_by(staff_id=staff.id).order_by(Leave.start_date.desc()).all()
    return render_template('staff_leave.html', leaves=leaves)

@app.route('/staff/payslips')
@staff_required
def staff_payslips():
    staff = Staff.query.filter_by(user_id=session['user_id']).first()
    payslips = PaySlip.query.filter_by(staff_id=staff.id).order_by(PaySlip.period_end.desc()).all()
    
    total_earnings = sum(payslip.gross_pay for payslip in payslips)
    total_deductions = sum(payslip.deductions for payslip in payslips)
    
    return render_template('staff_payslips.html', 
                           payslips=payslips, 
                           total_earnings=total_earnings, 
                           total_deductions=total_deductions)

@app.route('/staff/view_payslip/<int:payslip_id>')
@staff_required
def view_payslip(payslip_id):
    payslip = PaySlip.query.get_or_404(payslip_id)
    if payslip.staff_id != Staff.query.filter_by(user_id=session['user_id']).first().id:
        flash('You are not authorized to view this payslip.', 'error')
        return redirect(url_for('staff_payslips'))
    return render_template('view_payslip.html', payslip=payslip)

@app.route('/staff/download_payslip/<int:payslip_id>')
@staff_required
def download_payslip(payslip_id):
    payslip = PaySlip.query.get_or_404(payslip_id)
    if payslip.staff_id != Staff.query.filter_by(user_id=session['user_id']).first().id:
        flash('You are not authorized to download this payslip.', 'error')
        return redirect(url_for('staff_payslips'))
    
    # Generate PDF payslip
    pdf = generate_payslip_pdf(payslip)
    
    # Create a response with the PDF
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=payslip_{payslip.period_start.strftime("%Y-%m-%d")}_to_{payslip.period_end.strftime("%Y-%m-%d")}.pdf'
    
    return response

def generate_payslip_pdf(payslip):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.drawString(100, 750, f"Payslip for {payslip.staff.user.first_name} {payslip.staff.user.last_name}")
    p.drawString(100, 700, f"Period: {payslip.period_start.strftime('%Y-%m-%d')} to {payslip.period_end.strftime('%Y-%m-%d')}")
    p.drawString(100, 650, f"Gross Pay: ${payslip.gross_pay:.2f}")
    p.drawString(100, 600, f"Deductions: ${payslip.deductions:.2f}")
    p.drawString(100, 550, f"Net Pay: ${payslip.net_pay:.2f}")
    p.showPage()
    p.save()

    pdf = buffer.getvalue()
    buffer.close()
    return pdf

@app.route('/admin/dashboard-data')
@admin_required
def admin_dashboard_data():
    total_applicants = Applicant.query.count()
    open_applications = ApplicationForm.query.filter_by(status='pending').count()
    scheduled_interviews = Interview.query.filter_by(status='scheduled').count()
    total_staff = Staff.query.count()
    
    application_status = {
        'pending': ApplicationForm.query.filter_by(status='pending').count(),
        'reviewing': ApplicationForm.query.filter_by(status='reviewing').count(),
        'accepted': ApplicationForm.query.filter_by(status='accepted').count(),
        'rejected': ApplicationForm.query.filter_by(status='rejected').count()
    }
    
    # Get attendance data for the last 7 days
    today = datetime.now().date()
    seven_days_ago = today - timedelta(days=7)
    attendance_data = db.session.query(
        Attendance.date,
        db.func.count(Attendance.id).label('present_count')
    ).filter(Attendance.date >= seven_days_ago).group_by(Attendance.date).all()
    
    attendance_dates = [(seven_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(8)]
    attendance_present = [0] * 8
    attendance_absent = [total_staff] * 8
    
    for date, present_count in attendance_data:
        index = (date - seven_days_ago).days
        attendance_present[index] = present_count
        attendance_absent[index] = total_staff - present_count
    
    recent_activities = []  # You can implement a system to track recent activities
    upcoming_interviews = Interview.query.filter(Interview.interview_date > datetime.now()).order_by(
Interview.interview_date).limit(5).all()

    return jsonify({
        'total_applicants': total_applicants,
        'open_applications': open_applications,
        'scheduled_interviews': scheduled_interviews,
        'total_staff': total_staff,
        'application_status': application_status,
        'attendance_dates': attendance_dates,
        'attendance_present': attendance_present,
        'attendance_absent': attendance_absent,
        'recent_activities': [{'description': activity.description, 'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for activity in recent_activities],
        'upcoming_interviews': [{'user_name': interview.applicant.user.first_name + ' ' + interview.applicant.user.last_name, 'interview_date': interview.interview_date.strftime('%Y-%m-%d %H:%M')} for interview in upcoming_interviews]
    })

@app.route('/admin/attendance-data')
@admin_required
def admin_attendance_data():
    staff_id = request.args.get('staff', 'all')
    date = request.args.get('date')
    period = request.args.get('period', 'day')

    query = Attendance.query

    if staff_id != 'all':
        query = query.filter(Attendance.staff_id == staff_id)

    if date:
        date = datetime.strptime(date, '%Y-%m-%d').date()
        if period == 'day':
            query = query.filter(Attendance.date == date)
        elif period == 'week':
            start_of_week = date - timedelta(days=date.weekday())
            end_of_week = start_of_week + timedelta(days=6)
            query = query.filter(Attendance.date.between(start_of_week, end_of_week))
        elif period == 'month':
            start_of_month = date.replace(day=1)
            end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            query = query.filter(Attendance.date.between(start_of_month, end_of_month))
        elif period == 'year':
            start_of_year = date.replace(month=1, day=1)
            end_of_year = date.replace(month=12, day=31)
            query = query.filter(Attendance.date.between(start_of_year, end_of_year))

    attendances = query.order_by(Attendance.date.desc()).all()

    return jsonify([
        {
            'staff_name': attendance.staff.user.first_name + ' ' + attendance.staff.user.last_name,
            'date': attendance.date.strftime('%Y-%m-%d'),
            'check_in': attendance.check_in.strftime('%H:%M:%S') if attendance.check_in else None,
            'check_out': attendance.check_out.strftime('%H:%M:%S') if attendance.check_out else None,
            'total_hours': str(attendance.check_out - attendance.check_in) if attendance.check_out else None,
            'id': attendance.id
        }
        for attendance in attendances
    ])

@app.route('/admin/leaves')
@admin_required
def admin_leaves():
    leaves = Leave.query.all()
    return render_template('admin_leaves.html', leaves=leaves)

@app.route('/applicant/romn_compliance', methods=['GET', 'POST'])
@login_required
def romn_compliance():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))

    existing_compliance = ROMNCompliance.query.filter_by(applicant_id=applicant.id).first()

    if request.method == 'POST' and not existing_compliance:
        signature = request.form['signature']
        new_compliance = ROMNCompliance(applicant_id=applicant.id, signature=signature)
        db.session.add(new_compliance)
        db.session.commit()
        flash('ROMN compliance submitted successfully.', 'success')
        return redirect(url_for('applicant_dashboard'))

    return render_template('romn_compliance.html', romn_compliance=existing_compliance)

@app.route('/applicant/policy_agreement', methods=['GET', 'POST'])
@login_required
def policy_agreement():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))
    existing_agreement = PolicyAgreement.query.filter_by(applicant_id=applicant.id).first()
    if request.method == 'POST' and not existing_agreement:
        new_agreement = PolicyAgreement(applicant_id=applicant.id)
        db.session.add(new_agreement)
        db.session.commit()
        flash('Policy agreement submitted successfully.', 'success')
        return redirect(url_for('applicant_dashboard'))
    return render_template('policy_agreement.html', policy_agreement=existing_agreement)

@app.route('/applicant/audit_declaration', methods=['GET', 'POST'])
@login_required
def audit_declaration():
    applicant = Applicant.query.filter_by(user_id=session['user_id']).first()
    if not applicant:
        flash('Applicant profile not found.', 'error')
        return redirect(url_for('applicant_dashboard'))

    existing_declaration = AuditDeclaration.query.filter_by(applicant_id=applicant.id).first()

    if request.method == 'POST' and not existing_declaration:
        signature = request.form['signature']
        new_declaration = AuditDeclaration(applicant_id=applicant.id, signature=signature)
        db.session.add(new_declaration)
        db.session.commit()
        flash('Audit declaration submitted successfully.', 'success')
        return redirect(url_for('applicant_dashboard'))

    return render_template('audit_declaration.html', audit_declaration=existing_declaration)

@app.route('/download_audit_declaration/<int:declaration_id>')
@login_required
def download_audit_declaration(declaration_id):
    declaration = AuditDeclaration.query.get_or_404(declaration_id)
    if declaration.applicant.user_id != session['user_id']:
        flash('You are not authorized to download this file.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    if declaration.file_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], declaration.file_path)):
        return send_from_directory(app.config['UPLOAD_FOLDER'], declaration.file_path, as_attachment=True)
    else:
        flash('Audit declaration file not found.', 'error')
        return redirect(url_for('applicant_dashboard'))

@app.route('/download_romn_compliance/<int:compliance_id>')
@login_required
def download_romn_compliance(compliance_id):
    compliance = ROMNCompliance.query.get_or_404(compliance_id)
    if compliance.applicant.user_id != session['user_id']:
        flash('You are not authorized to download this file.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    if compliance.file_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], compliance.file_path)):
        return send_from_directory(app.config['UPLOAD_FOLDER'], compliance.file_path, as_attachment=True)
    else:
        flash('ROMN compliance file not found.', 'error')
        return redirect(url_for('applicant_dashboard'))

@app.route('/download_policy_agreement/<int:agreement_id>')
@login_required
def download_policy_agreement(agreement_id):
    agreement = PolicyAgreement.query.get_or_404(agreement_id)
    if agreement.applicant.user_id != session['user_id']:
        flash('You are not authorized to download this file.', 'error')
        return redirect(url_for('applicant_dashboard'))
    
    if agreement.file_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], agreement.file_path)):
        return send_from_directory(app.config['UPLOAD_FOLDER'], agreement.file_path, as_attachment=True)
    else:
        flash('Policy agreement file not found.', 'error')
        return redirect(url_for('applicant_dashboard'))

@app.route('/admin/view_staff/<int:staff_id>')
@admin_required
def admin_view_staff(staff_id):
    staff = Staff.query.get_or_404(staff_id)
    return render_template('admin_view_staff.html', staff=staff)

@app.route('/download_application_form/<int:application_id>')
@login_required
def download_application_form(application_id):
    application = ApplicationForm.query.get_or_404(application_id)
    # Generate PDF here
    # For demonstration, we'll just return a text file
    return send_file(io.BytesIO(str(application).encode()), 
                     attachment_filename='application_form.txt',
                     as_attachment=True)

@app.route('/admin/view_applicant_documents/<int:applicant_id>')
@admin_required
def view_applicant_documents(applicant_id):
    applicant = Applicant.query.get_or_404(applicant_id)
    documents = Document.query.filter_by(applicant_id=applicant_id).all()
    return render_template('admin_view_documents.html', applicant=applicant, documents=documents)

@app.route('/admin/download_document/<int:document_id>')
@admin_required
def admin_download_document(document_id):
    document = Document.query.get_or_404(document_id)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], document.file_path),
                     as_attachment=True)

def init_db():
    with app.app_context():
        db.create_all()
        
        # Check if test user already exists
        test_user = User.query.filter_by(email='test@example.com').first()
        if not test_user:
            test_user = User(
                email='test@example.com',
                password=generate_password_hash('password123'),
                role='applicant',
                phone_number='1234567890',
                recovery_password=generate_password_hash('recovery123')
            )
            db.session.add(test_user)
            db.session.commit()
            print("Test user created.")
        else:
            print("Test user already exists.")
        
def create_admin_user():
    with app.app_context():
        admin_user = User.query.filter_by(email='miracle@admin.com').first()
        if not admin_user:
            admin_user = User(
                email='miracle@admin.com',
                password=generate_password_hash('001230'),
                role='admin',
                phone_number='1234567890',
                recovery_password=generate_password_hash('admin_recovery'),
                first_name='Miracle',
                last_name='Admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created.")
        else:
            print("Admin user already exists.")

def create_test_staff():
    with app.app_context():
        test_staff = User.query.filter_by(email='staff@example.com').first()
        if not test_staff:
            test_staff = User(
                email='staff@example.com',
                password=generate_password_hash('staffpass123'),
                role='staff',
                phone_number='9876543210',
                recovery_password=generate_password_hash('staffrecovery123'),
                first_name='Test',
                last_name='Staff'
            )
            db.session.add(test_staff)
            db.session.commit()

            staff = Staff(
                user_id=test_staff.id,
                position='Nurse',
                department='Emergency',
                hire_date=datetime.now().date()
            )
            db.session.add(staff)
            db.session.commit()
            print("Test staff user created.")
        else:
            print("Test staff user already exists.")

if __name__ == '__main__':
    with app.app_context():
        init_db()
        create_admin_user()
        create_test_staff()
    app.run(debug=True)

