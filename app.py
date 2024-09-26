from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, Response
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired
import os
import redis
import psycopg2
from dotenv import load_dotenv
import time

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
    username = session.get('username', None)
    return render_template('home.html', username=username)

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
            session['username'] = admin[1]
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials, please try again.')
    return render_template('admin_login.html')

@app.route('/get_new_messages', methods=['GET'])
def get_new_messages():
    user_id = session.get('username')
    if not user_id:
        return jsonify({'messages': []})

    messages = redis_client.lrange(f'conversation:{user_id}:admin', 0, -1)
    return jsonify({'messages': messages})

def stream_messages():
    user_id = session.get('username')
    pubsub = redis_client.pubsub()
    pubsub.subscribe(f'conversation:{user_id}:admin')
    for message in pubsub.listen():
        if message['type'] == 'message':
            yield f"data: {message['data']}\n\n"
            time.sleep(1)

@app.route('/message_stream')
def message_stream():
    return Response(stream_messages(), mimetype='text/event-stream')

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

    unread_count = redis_client.get('unread_messages') or 0
    conversation_keys = redis_client.keys('conversation:*:admin')
    conversations = []

    for key in conversation_keys:
        messages = redis_client.lrange(key, 0, -1)
        conversations.append({
            'user_id': key.split(':')[1],
            'messages': messages
        })

    return render_template('admin_dashboard.html', form=form, conversations=conversations, unread_count=unread_count)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/tours', methods=['GET', 'POST'])
def admin_tours():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    return render_template('tourupload.html')

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
            session['username'] = user[1]
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, please try again.')

    return render_template('login.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if not session.get('user_logged_in'):
        flash('You need to log in to send messages.')
        return redirect(url_for('user_login'))

    user_id = session.get('username')
    if request.method == 'POST':
        message = request.form['message']
        if message.strip():
            redis_client.rpush(f'conversation:{user_id}:admin', f'user:{message}')
            redis_client.incr('unread_messages')
            flash('Message sent to the admin!')
        else:
            flash('Message cannot be empty.')
        
        # Redirect after POST to avoid form resubmission
        return redirect(url_for('contact'))

    messages = redis_client.lrange(f'conversation:{user_id}:admin', 0, -1)
    return render_template('contact.html', messages=messages)


@app.route('/admin/reply/<user_id>', methods=['GET', 'POST'], endpoint='admin_reply_user')
def admin_reply(user_id):
    if request.method == 'POST':
        message = request.form['reply']
        if message:
            redis_client.rpush(f'conversation:{user_id}:admin', f"admin:{message}")
        redis_client.set('unread_messages', max(0, int(redis_client.get('unread_messages') or 1) - 1))
        return redirect(url_for('admin_reply_user', user_id=user_id))

    messages = redis_client.lrange(f'conversation:{user_id}:admin', 0, -1)
    return render_template('admin_reply.html', messages=messages, user_id=user_id)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('username', None)
    return redirect(url_for('admin_login'))

@app.route('/user/logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('username', None)
    return redirect(url_for('user_login'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_pg()
    app.run(debug=True)
