from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_PATH'] = 1024 * 1024 * 20


class UploadForm(FlaskForm):
    photo = FileField('Photo', validators=[DataRequired()])
    submit = SubmitField('Upload')


def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS example_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute("INSERT OR IGNORE INTO admin (username, password) VALUES (?, ?)", ('admin', 'password'))
    c.execute('''
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/gallery')
def gallery():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT filename FROM images')
    images = c.fetchall()
    conn.close()
    return render_template('gallery.html', images=images, enumerate=enumerate)


@app.route('/tours')
def tours():
    return render_template('tours.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM admin WHERE username = ? AND password = ?', (username, password))
        admin = c.fetchone()
        conn.close()
        if admin:
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
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO images (filename) VALUES (?)", (filename,))
        conn.commit()
        conn.close()
        flash('Image successfully uploaded and saved.')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_dashboard.html', form=form)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


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
    init_db()
    app.run(debug=True)
