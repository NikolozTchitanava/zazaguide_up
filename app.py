from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired
import os
import redis
import psycopg2
from dotenv import load_dotenv

load_dotenv(verbose=True, override=True)

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_PATH'] = 1024 * 1024 * 20

password = os.getenv("PASSWORD")

redis_client = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)

pg_conn = psycopg2.connect(user="postgres", password="mysecretpassword", host="localhost", port="5432")
pg_cursor = pg_conn.cursor()

class UploadForm(FlaskForm):
    photo = FileField('Photo', validators=[DataRequired()])
    submit = SubmitField('Upload')

def init_pg():
    pg_cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email VARCHAR(100) NOT NULL,
            telegram_account VARCHAR(100)
        )
    ''')
    pg_conn.commit()

    try:
        pg_cursor.execute("SELECT usertype FROM users LIMIT 1")
    except psycopg2.errors.UndefinedColumn:
        pg_conn.rollback()
        pg_cursor.execute("ALTER TABLE users ADD COLUMN usertype INT NOT NULL DEFAULT 0")
        pg_conn.commit()

    pg_cursor.execute("SELECT * FROM users WHERE username = %s", ('admin',))
    admin = pg_cursor.fetchone()
    if not admin:
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        pg_cursor.execute(
            "INSERT INTO users (username, password, email, usertype, telegram_account) VALUES (%s, %s, %s, %s, %s)",
            ('admin', hashed_password, 'admin@example.com', 1, 'admin_telegram')
        )
        pg_conn.commit()

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/gallery')
def gallery():
    image_list = redis_client.lrange('images', 0, -1)
    return render_template('gallery.html', images=image_list, enumerate=enumerate)

@app.route('/tours')
def tours():
    return render_template('tours.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pg_cursor.execute('SELECT * FROM users WHERE username = %s AND usertype = 1', (username,))
        admin = pg_cursor.fetchone()

        if admin and check_password_hash(admin[2], password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials, please try again.')
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    form = UploadForm()
    if form.validate_on_submit():
        file = form.photo.data
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        redis_client.rpush('images', filename)
        flash('Image successfully uploaded and saved.')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_dashboard.html', form=form)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        telegram_account = request.form.get('telegram_account')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            pg_cursor.execute(
                "INSERT INTO users (username, password, email, usertype, telegram_account) VALUES (%s, %s, %s, %s, %s)",
                (username, hashed_password, email, 0, telegram_account)
            )
            pg_conn.commit()
            flash('Signup successful! Please login.')
            return redirect(url_for('user_login'))
        except psycopg2.IntegrityError:
            pg_conn.rollback()
            flash('Username already exists. Please choose another.')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pg_cursor.execute('SELECT * FROM users WHERE username = %s AND usertype = 0', (username,))
        user = pg_cursor.fetchone()
        
        if user and check_password_hash(user[2], password):
            session['user_logged_in'] = True
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, please try again.')
    
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_pg()
    app.run(debug=True)
