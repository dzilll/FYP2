from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import re
import os
import bcrypt
from datetime import datetime
from flask_talisman import Talisman
from flask_migrate import Migrate
from flask_limiter import Limiter

# Initialize the Flask application
app = Flask(__name__)

# Secret key for session and flash messages (Use environment variable for production)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')  # For production, use an env variable
talisman = Talisman(app)
limiter = Limiter(app)


# X-Content-Type-Options to prevent MIME sniffing
app.config['TALISMAN_CONTENT_TYPE_OPTIONS'] = 'nosniff'

# Prevent your site from being embedded in an iframe
app.config['TALISMAN_X_FRAME_OPTIONS'] = 'DENY'

# Enable XSS protection in supported browsers
app.config['TALISMAN_X_XSS_PROTECTION'] = True



app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # Default role is 'user'
    

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


        # Method to set hashed password using bcrypt
    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Add this method to check password using bcrypt
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def rehash_passwords():
        users = User.query.all()
        for user in users:
            # Check if the password is using bcrypt
            if not bcrypt.checkpw("existing_password".encode('utf-8'), user.password.encode('utf-8')):
                new_password_hash = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                user.password = new_password_hash
                db.session.commit()


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    issues = db.Column(db.Text, nullable=True)  # store issues found
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Use a unique backref name for scans
    user = db.relationship('User', backref='scans', lazy=True)  # Changed from 'user' to 'scans'


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)



# Routes

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        # Create a new user and set password
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
     if request.method == 'POST':
         username = request.form['username']
         password = request.form['password']

         user = User.query.filter_by(username=username).first()
         if user and user.check_password(password):
             session['user_id'] = user.id
             flash('Login successful!', 'success')
             return redirect(url_for('home'))
         else:
             flash('Invalid username or password.', 'error')

     return render_template('login.html')


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    return render_template('home.html', user_id=user_id, username=user.username)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))



def scan_file_for_injection(filepath):
    findings = []

    # Patterns for different types of injection
    sql_patterns = [
        r'(mysql_query|mysqli_query|pdo->query|pdo->exec)\s*\(.*\)',
        r'\b(select|insert|update|delete|drop|create|alter|union)\b.*',
        r'(CONCAT|GROUP_CONCAT|EXTRACTVALUE|LOAD_FILE)\s*\(.*\)',
        r'\bAND\s+1=1\b',
        r'\bOR\s+1=1\b',
        r'\bAND\s+1=1\s*--\b',
        r'\bOR\s+1=1\s*--\b',
        r'SLEEP\(\d+\)',
        r'\b(AND|OR)\s+\d+\s*=\s*\d+\s*SLEEP\(\d+\)',
        r'WAITFOR\s+DELAY\s+\'\d+\:\d+\:\d+\'',
    ]

    command_injection_patterns = [
        r'\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(.*\)',
        r'\b(\|\||&&|\|)\s*.*\b',
    ]

    ldap_injection_patterns = [
        r'ldap_search\((.*)\)',
        r'(&\(.*\))',
    ]

    xml_injection_patterns = [
        r'<!DOCTYPE\s+\w+\s*\[.*\]>',
        r'<\?xml.*\?>',
        r'<\w+.*>.*</\w+>',
    ]

    xss_patterns = [
        r'<script.*?>.*</script>',
        r'script',
        r'on\w+\s*=\s*["\'].*["\']',
        r'javascript:.*',
        r'<img.*?src=".*">',
    ]

    # Read file contents
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        for pattern_group, vuln_type, suggestion in [
            (sql_patterns, "SQL injection", "Use prepared statements and parameterized queries."),
            (command_injection_patterns, "Command injection", "Avoid system calls or sanitize inputs using escapeshellcmd()."),
            (ldap_injection_patterns, "LDAP injection", "Use prepared LDAP queries or sanitize user input."),
            (xml_injection_patterns, "XML injection", "Sanitize inputs and disable external entities."),
            (xss_patterns, "Cross-site Scripting (XSS)", "Sanitize user inputs and use secure output encoding."),
        ]:
            for pattern in pattern_group:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        findings.append({
                            'file': os.path.basename(filepath),
                            'issue': f"{vuln_type} vulnerability detected on line {i}: {stripped} Suggestion: {suggestion}"
                        })
                except re.error as e:
                    print(f"Regex error: {e} in pattern: {pattern}")

    return findings



@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        feedback_text = request.form['feedback']
        user_id = session.get('user_id')

        if user_id:
            # Create and save new feedback
            new_feedback = Feedback(user_id=user_id, text=feedback_text)
            db.session.add(new_feedback)
            db.session.commit()
            flash('Thank you for your feedback!', 'success')
        else:
            flash('You must be logged in to submit feedback.', 'error')
        
        return redirect(url_for('dashboard'))  # Redirect to the dashboard after submitting

    return render_template('feedback.html')


UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload_scan', methods=['POST'])
def upload_scan():
    if 'file' not in request.files:
        return 'No file uploaded', 400

    file = request.files['file']
    if file.filename == '':
        return 'No file selected', 400

    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in to upload files.", "error")
        return redirect(url_for('login'))

    # Save the uploaded file
    filename = secure_filename(file.filename)
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    print(f"File uploaded successfully: {filename}")  # Debugging statement

    # Initialize scan_id
    scan_id = None

    # Scan the uploaded file for SQL Injection
    issues = scan_file_for_injection(upload_path)

    if issues:
        for issue in issues:
            print(issue['issue'])  # Debugging statement for detected issues

        # Save scan results in DB
        new_scan = Scan(
            user_id=user_id,
            filename=filename,
            issues="\n".join([issue['issue'] for issue in issues])
        )
        db.session.add(new_scan)
        db.session.commit()

        scan_id = new_scan.id  # Get the scan ID to redirect to view_scan
        flash(f"Scan complete! Issues found.", "error")
    else:
        # If no issues found, store "No issues found" in the database
        new_scan = Scan(
            user_id=user_id,
            filename=filename,
            issues="No issues found"
        )
        db.session.add(new_scan)
        db.session.commit()

        scan_id = new_scan.id  # Get the scan ID to redirect to view_scan
        flash("No issues found in the uploaded file.", "success")

    # Ensure scan_id is valid before redirecting
    if scan_id:
        return redirect(url_for('view_scan', scan_id=scan_id))  # Redirect to view_scan page with the scan ID
    else:
        return redirect(url_for('view_scan'))  # Redirect to home if no scan was performed or no issues were found

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)  # Fetch user from the database

    # Get user's scan history
    user_scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.timestamp.desc()).all()

    # Get user's feedback history
    feedback_list = Feedback.query.filter_by(user_id=user_id).all()

    return render_template('dashboard.html', user=user, scans=user_scans, feedback_list=feedback_list)

@app.route('/view_scan/<int:scan_id>')
def view_scan(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    scan = Scan.query.get_or_404(scan_id)

    # Security: Only allow owner to view the scan results
    if scan.user_id != session['user_id']:
        return 'Unauthorized', 403

    # Display the scan results (issues found in the scanned PHP file)
    scan_content = scan.issues

    return render_template('view_scan.html', scan=scan, content=scan_content)

@app.route('/sast-awareness')
def sast_awareness():
    return render_template('sast_awareness.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)  # Run the Flask app in debug mode