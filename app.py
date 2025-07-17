from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secret_key'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

users = {}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in users else None

ALLOWED_EXTENSIONS = {'xls', 'xlsx'}
UPLOAD_FOLDER = 'uploaded_excels'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        if u in users:
            flash('Username already taken')
        else:
            users[u] = {'password_hash': generate_password_hash(p)}
            flash('Registered! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        user = users.get(u)
        if user and check_password_hash(user['password_hash'], p):
            login_user(User(u))
            flash('Logged in successfully.')
            return redirect(url_for('welcome'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('welcome'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            flash(f'File "{filename}" uploaded successfully!')
            return redirect(url_for('admin_upload'))
        else:
            flash('Allowed file types are xls, xlsx')
            return redirect(request.url)

    files = os.listdir(UPLOAD_FOLDER)
    return render_template('admin.html', files=files)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_ppr():
    all_files = [os.path.join(UPLOAD_FOLDER, f) for f in os.listdir(UPLOAD_FOLDER) if allowed_file(f)]

    if not all_files:
        flash('No Excel files uploaded by admin yet.')
        return redirect(url_for('admin_upload'))

    try:
        dfs = [pd.read_excel(f) for f in all_files]
        combined_df = pd.concat(dfs, ignore_index=True)
    except Exception as e:
        flash(f'Error reading Excel files: {e}')
        return redirect(url_for('admin_upload'))

    if not {'Name', 'CIN', 'PPR'}.issubset(combined_df.columns):
        flash('Excel files must contain: Name, CIN, PPR')
        return redirect(url_for('admin_upload'))

    result = None
    if request.method == 'POST':
        search_input = request.form['search_input'].strip().lower()

        try:
            match = combined_df[
                combined_df['Name'].astype(str).str.lower().str.contains(search_input) |
                combined_df['CIN'].astype(str).str.lower().str.contains(search_input)
            ]

            if not match.empty:
                result = match[['Name', 'CIN', 'PPR']].to_dict(orient='records')
            else:
                result = "No match found."
        except Exception as e:
            flash(f'Error during search: {e}')
            return redirect(url_for('search_ppr'))

    return render_template('search.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)