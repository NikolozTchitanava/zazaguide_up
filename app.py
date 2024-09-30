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
from datetime import datetime

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

    pg_cursor.execute('''
        CREATE TABLE IF NOT EXISTS tours (
            tour_id SERIAL PRIMARY KEY,
            tour_name VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            location VARCHAR(255),
            tags VARCHAR(255),
            tour_length INT NOT NULL,
            hardship_level INT NOT NULL,
            possible_months VARCHAR(255),
            price DECIMAL(10, 2) NOT NULL,
            images TEXT
        )
    ''')
    pg_conn.commit()

    pg_cursor.execute('''
        CREATE TABLE IF NOT EXISTS confirmed_bookings (
            booking_id SERIAL PRIMARY KEY,
            user_id INT,
            username VARCHAR(100),
            telegram_account VARCHAR(100),
            tour_id INT,
            tourname VARCHAR(255),
            tour_date DATE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (tour_id) REFERENCES tours(tour_id)
        )
    ''')
    pg_conn.commit()

    pg_cursor.execute('''
    CREATE TABLE IF NOT EXISTS booking_requests (
        request_id SERIAL PRIMARY KEY,
        user_id INT,
        username VARCHAR(100),
        tour_id INT,
        tourname VARCHAR(255),
        tour_date DATE,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (tour_id) REFERENCES tours(tour_id)
    )
    ''')
    pg_conn.commit()


@app.route('/home')
def home():
    username = session.get('username', None)

    pg_cursor.execute('''
        SELECT cb.tour_id, t.tour_name, cb.tour_date 
        FROM confirmed_bookings cb 
        JOIN tours t ON cb.tour_id = t.tour_id
        JOIN users u ON cb.user_id = u.id
        WHERE u.username = %s
    ''', (username,))
    
    confirmed_bookings = pg_cursor.fetchall()
    
    return render_template('home.html', username=username, confirmed_bookings=confirmed_bookings)


@app.route('/admin/confirm_request/<int:request_id>', methods=['POST'])
def confirm_request(request_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    pg_cursor.execute('SELECT * FROM booking_requests WHERE request_id = %s', (request_id,))
    request = pg_cursor.fetchone()

    if not request:
        flash('Request not found.')
        return redirect(url_for('admin_requests'))

    user_id, username, tour_id, tourname, tour_date = request[1], request[2], request[3], request[4], request[5]

    pg_cursor.execute('''
        INSERT INTO confirmed_bookings (user_id, username, telegram_account, tour_id, tourname, tour_date)
        SELECT u.id, u.username, u.telegram_account, %s, %s, %s
        FROM users u
        WHERE u.id = %s
    ''', (tour_id, tourname, tour_date, user_id))
    pg_conn.commit()

    pg_cursor.execute('DELETE FROM booking_requests WHERE request_id = %s', (request_id,))
    pg_conn.commit()

    flash('Booking confirmed.')
    return redirect(url_for('admin_requests'))

@app.route('/admin/requests')
def admin_requests():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    pg_cursor.execute('SELECT request_id, username, tourname, tour_date FROM booking_requests')
    requests = pg_cursor.fetchall()

    return render_template('requests.html', requests=requests)

@app.route('/gallery')
def gallery():
    image_list = redis_client.lrange('images', 0, -1)
    return render_template('gallery.html', images=image_list, enumerate=enumerate)

@app.route('/tours')
def tours():
    pg_cursor.execute('SELECT tour_id, tour_name, location, images FROM tours')
    tours = pg_cursor.fetchall()
    return render_template('tours.html', tours=tours)

@app.route('/booking/<int:tour_id>', methods=['GET', 'POST'])
def booking(tour_id):
    pg_cursor.execute('SELECT tour_name, possible_months FROM tours WHERE tour_id = %s', (tour_id,))
    tour = pg_cursor.fetchone()

    if not tour:
        flash('Tour not found.')
        return redirect(url_for('tours'))

    if request.method == 'POST':
        selected_date = request.form.get('selected_date')

        pg_cursor.execute('''
            SELECT * FROM confirmed_bookings 
            WHERE tour_id = %s AND tour_date = %s
        ''', (tour_id, selected_date))
        existing_booking = pg_cursor.fetchone()

        if existing_booking:
            flash(f'Day {selected_date} is already booked, please choose a different date.')
            return render_template('booking.html', tour=tour)

        selected_month = datetime.strptime(selected_date, '%Y-%m-%d').strftime('%B')
        possible_months = tour[1].split(',')

        if selected_month not in possible_months:
            flash(f'Selected date {selected_date} is not in the eligible months for this tour.')
            return render_template('booking.html', tour=tour)

        user_id = session.get('user_id')
        username = session.get('username')

        if not user_id or not username:
            flash('Please log in to make a booking.')
            return redirect(url_for('user_login'))


        pg_cursor.execute('''
            INSERT INTO booking_requests (user_id, username, tour_id, tourname, tour_date)
            VALUES (%s, %s, %s, %s, %s)
        ''', (user_id, username, tour_id, tour[0], selected_date))
        pg_conn.commit()

        flash(f'Booking request sent for {tour[0]} on {selected_date}. Awaiting admin confirmation.')
        return redirect(url_for('home'))

    return render_template('booking.html', tour=tour)


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

@app.route('/admin/edit_tour/<int:tour_id>', methods=['GET', 'POST'])
def edit_tour(tour_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    pg_cursor.execute('SELECT * FROM tours WHERE tour_id = %s', (tour_id,))
    tour = pg_cursor.fetchone()

    if not tour:
        flash('Tour not found.')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        tour_name = request.form.get('tour_name')
        description = request.form.get('description')
        location = request.form.get('location')
        tags = request.form.get('tags')
        tour_length = request.form.get('tour_length')
        hardship_level = request.form.get('hardship_level')
        possible_months = ','.join(request.form.getlist('possible_months'))
        price = request.form.get('price')

        try:
            pg_cursor.execute('''
                UPDATE tours 
                SET tour_name = %s, description = %s, location = %s, tags = %s, tour_length = %s, 
                    hardship_level = %s, possible_months = %s, price = %s 
                WHERE tour_id = %s
            ''', (tour_name, description, location, tags, tour_length, hardship_level, possible_months, price, tour_id))
            pg_conn.commit()
            flash('Tour successfully updated.')
        except Exception as e:
            pg_conn.rollback()
            flash('Failed to update tour. Please try again.')

        return redirect(url_for('admin_dashboard'))

    return render_template('edit_tour.html', tour=tour)


@app.route('/admin/delete_tour/<int:tour_id>', methods=['POST'])
def delete_tour(tour_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    try:
        pg_cursor.execute('DELETE FROM tours WHERE tour_id = %s', (tour_id,))
        pg_conn.commit()
        flash('Tour successfully deleted.')
    except Exception as e:
        pg_conn.rollback()
        flash('Failed to delete tour. Please try again.')

    return redirect(url_for('admin_dashboard'))

@app.route('/get_new_messages', methods=['GET'])
def get_new_messages():
    user_id = session.get('username')
    if not user_id:
        return jsonify({'messages': []})

    # Fetch messages from Redis
    try:
        raw_messages = redis_client.lrange(f'conversation:{user_id}:admin', 0, -1)
    except Exception as e:
        return jsonify({'error': 'Error retrieving messages'}), 500

    messages = []
    for idx, raw_message in enumerate(raw_messages):
        try:
            message_data = raw_message.split(":", 1)
            if len(message_data) == 2:
                sender, message = message_data
                messages.append({
                    'id': idx,  # Use the index of the message as ID
                    'message': message,
                    'sender': sender
                })
        except (IndexError, ValueError):
            continue

    return jsonify({'messages': messages})


def stream_messages():
    user_id = session.get('username')
    if not user_id:
        return

    pubsub = redis_client.pubsub()

    # Subscribe to the user's conversation channel
    try:
        pubsub.subscribe(f'conversation:{user_id}:admin')
    except Exception as e:
        yield f"data: Error subscribing to message channel\n\n"
        return

    # Stream new messages
    for message in pubsub.listen():
        if message['type'] == 'message':
            yield f"data: {message['data']}\n\n"
            time.sleep(1)


@app.route('/message_stream')
def message_stream():
    user_id = session.get('username')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

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

    pg_cursor.execute('SELECT tour_id, tour_name, location, price FROM tours')
    tours = pg_cursor.fetchall()

    pg_cursor.execute('SELECT username, tourname, tour_date FROM confirmed_bookings')
    confirmed_bookings = pg_cursor.fetchall()

    return render_template(
        'admin_dashboard.html', 
        form=form, 
        conversations=conversations, 
        unread_count=unread_count, 
        tours=tours,
        confirmed_bookings=confirmed_bookings
    )

    return render_template('admin_dashboard.html', form=form, conversations=conversations, unread_count=unread_count, tours=tours)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/tours', methods=['GET', 'POST'])
def admin_tours():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    form = UploadForm()  

    if request.method == 'POST' :
        photos = request.files.getlist('photos')
        tour_name = request.form.get('tour_name')
        description = request.form.get('description')
        location = request.form.get('location')
        tags = request.form.get('tags')
        tour_length = request.form.get('tour_length')
        hardship_level = request.form.get('hardship_level')
        possible_months = ','.join(request.form.getlist('possible_months'))
        price = request.form.get('price')

        image_filenames = []
        for photo in photos:
            filename = secure_filename(photo.filename)
            if filename:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(filepath)
                image_filenames.append(filename)

        images = ','.join(image_filenames) if image_filenames else None

        try:
            pg_cursor.execute('''
                INSERT INTO tours (tour_name, description, location, tags, tour_length, hardship_level, possible_months, price, images)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (tour_name, description, location, tags, tour_length, hardship_level, possible_months, price, images))
            pg_conn.commit()
            flash('Tour successfully uploaded!')
        except Exception as e:
            pg_conn.rollback()
            flash("Failed to upload tour. Please try again.")
        
        return redirect(url_for('admin_dashboard'))

    return render_template('tourupload.html', form=form)  # Pass the form to the template

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
@app.route('/tour_info/<int:tour_id>', methods=['GET'])
def tour_info(tour_id):
    pg_cursor.execute('SELECT tour_id, tour_name, description, location, tags, tour_length, hardship_level, possible_months, price, images FROM tours WHERE tour_id = %s', (tour_id,))
    tour = pg_cursor.fetchone()

    if not tour:
        flash('Tour not found.')
        return redirect(url_for('tours'))

    return render_template('tour_info.html', tour=tour)

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
    app.run(debug=True, host="0.0.0.0")
