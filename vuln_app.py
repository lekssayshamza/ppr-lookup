from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, UTC
from sqlalchemy import text

app = Flask(__name__, template_folder='templates_vulnerable')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['UPLOAD_FOLDER'] = 'uploaded_excels'
app.secret_key = 'eyJ1c2VybmFtZSI6ImFkbWluIn0.aIIZYg.0nA9d0WGome7mjiyU'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', backref=db.backref('files', lazy=True))

class PPRRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    cin = db.Column(db.String(128), nullable=False)
    ppr = db.Column(db.String(128), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'), nullable=False)
    file = db.relationship('UploadedFile', backref=db.backref('records', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        if User.query.filter_by(username=u).first():
            flash('Username already taken', 'error')
        else:
            new_user = User(username=u, password_hash=generate_password_hash(p))
            db.session.add(new_user)
            db.session.commit()
            flash('Registered! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# Has been tested
@app.route('/login', methods=['GET', 'POST'])
def login():
    sql_query = ""
    debug_info = ""

    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        query = text(f"SELECT * FROM user WHERE username = '{u}' AND password_hash = '{p}'")
        sql_query = str(query)

        result = db.session.execute(query).mappings().fetchone()

        if result:
            user = User.query.get(result['id'])
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('welcome'))
        else:
            safe_user = User.query.filter_by(username=u).first()
            if safe_user and check_password_hash(safe_user.password_hash, p):
                login_user(safe_user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('welcome'))
            else:
                debug_info = "No user found with those credentials"
                flash('Invalid credentials', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('welcome'))

# Has been tested
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']

        if not file or file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        uploaded_file = UploadedFile(
            filename=filename,
            upload_date=datetime.now(UTC),
            uploader_id=current_user.id
        )
        db.session.add(uploaded_file)
        db.session.commit()

        try:
            df = pd.read_excel(file_path)
            for _, row in df.iterrows():
                record = PPRRecord(
                    name=str(row['Name']),
                    cin=str(row['CIN']),
                    ppr=str(row['PPR']),
                    file_id=uploaded_file.id
                )
                db.session.add(record)
            db.session.commit()
            flash(f'File "{filename}" uploaded and data imported successfully!', 'success')
        except Exception as e:
            flash(f'Error importing Excel data: {e}', 'error')
            db.session.delete(uploaded_file)
            db.session.commit()
        return redirect(url_for('admin_upload'))

    files = UploadedFile.query.order_by(UploadedFile.upload_date.desc()).all()
    return render_template('admin.html', files=files)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_ppr():
    result = None
    if request.method == 'POST':
        search_input = request.form['search_input']
        try:
            matches = PPRRecord.query.filter(
                (PPRRecord.name.ilike(f"%{search_input}%")) |
                (PPRRecord.cin.ilike(f"%{search_input}%"))
            ).all()
            result = [{'Name': r.name, 'CIN': r.cin, 'PPR': r.ppr} for r in matches] or "No match found."
        except Exception as e:
            flash(f'Error during search: {e}', 'error')
            return redirect(url_for('search_ppr'))
    return render_template('search.html', result=result)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)