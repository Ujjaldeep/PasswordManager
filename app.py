from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from database import db, User, PasswordEntry
from encdec import encryptor, decryptor
import logging
import re
import uuid

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '8ba678f2332619424e00a1b97ae2f8dc'  # Replace with a secure key
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.errorhandler(404)
def page_not_found(e):
    logging.error(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))
        if not re.match(r'^[a-zA-Z0-9_@.]+$', username):
            flash('Invalid username: Use only letters, numbers, underscores, @, or .', 'error')
            return redirect(url_for('signup'))
        if len(password) < 6 or ' ' in password or not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', password):
            flash('Password must be at least 6 characters, no spaces, and only !@#$%_+.-, alphabets, numbers.', 'error')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        unique_key = str(uuid.uuid4())
        user = User(username=username, password=hashed_password, unique_key=unique_key)
        db.session.add(user)
        db.session.commit()
        
        flash(f'Account created! Your unique key is: {unique_key}. Save it securely!', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        unique_key = request.form['unique_key']
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password) and user.unique_key == unique_key:
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username, password, or unique key.', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        purpose = request.form['Purpose'].strip()
        entry_username = request.form['Username'].strip()
        pwd = request.form['Password'].strip()

        if not purpose or not entry_username or not pwd:
            flash("All fields are required", "error")
            return redirect(url_for('home'))
        if not re.match(r'^[a-zA-Z0-9_@.]+$', entry_username):
            flash("Invalid username: Use only letters, numbers, underscores, @, or .", "error")
            return redirect(url_for('home'))
        if len(pwd) < 6:
            flash("Password must be at least 6 characters long", "error")
            return redirect(url_for('home'))
        if ' ' in pwd:
            flash("Password cannot contain spaces", "error")
            return redirect(url_for('home'))
        if not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', pwd):
            flash("Password can only contain !@#$%_+.-, alphabets, and numbers", "error")
            logging.warning(f"Invalid password characters detected: {pwd}")
            return redirect(url_for('home'))
        if PasswordEntry.query.filter_by(user_id=current_user.id, entry_username=entry_username).first():
            flash("Username already exists for this user", "error")
            return redirect(url_for('home'))

        enc_data = encryptor(entry_username, pwd)
        new_entry = PasswordEntry(purpose=purpose, user_id=current_user.id, entry_username=entry_username, data=enc_data)
        try:
            db.session.add(new_entry)
            db.session.commit()
            flash("Entry added successfully", "success")
        except Exception as e:
            logging.error(f"Error adding entry {entry_username}: {e}")
            flash(f"Error saving entry: {e}", "error")
        return redirect(url_for('home'))
    else:
        entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
        datalist = []
        for e in entries:
            try:
                dec = decryptor(e.data)
                if not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', dec[1]):
                    logging.warning(f"Invalid characters in decrypted password for entry_username {e.entry_username}: {dec[1]}")
                    datalist.append([e.purpose, e.entry_username, "Invalid password characters"])
                else:
                    datalist.append([e.purpose, e.entry_username, dec[1]])
            except Exception as e:
                logging.error(f"Error decrypting for entry_username {e.entry_username}: {e}")
                datalist.append([e.purpose, e.entry_username, "Decryption failed"])
        return render_template('index.html', datalist=datalist)

@app.route('/delete/<string:entry_username>')
@login_required
def delete(entry_username):
    if not entry_username:
        logging.error("Empty entry_username in delete route")
        abort(404)
    del_cred = PasswordEntry.query.filter_by(user_id=current_user.id, entry_username=entry_username).first_or_404()
    try:
        db.session.delete(del_cred)
        db.session.commit()
        flash(f"Deleted entry for {entry_username}", "success")
        return redirect(url_for('home'))
    except Exception as e:
        logging.error(f"Error deleting entry_username {entry_username}: {e}")
        flash(f"Error deleting entry: {e}", "error")
        return redirect(url_for('home'))

@app.route('/update/<string:entry_username>', methods=['GET', 'POST'])
@login_required
def update(entry_username):
    entry = PasswordEntry.query.filter_by(user_id=current_user.id, entry_username=entry_username).first_or_404()
    if request.method == 'POST':
        purpose = request.form['Purpose'].strip()
        new_entry_username = request.form['Username'].strip()
        pwd = request.form['Password'].strip()

        if not purpose or not new_entry_username or not pwd:
            flash("All fields are required", "error")
            return render_template('update.html', entry=entry)
        if not re.match(r'^[a-zA-Z0-9_@.]+$', new_entry_username):
            flash("Invalid username: Use only letters, numbers, underscores, @, or .", "error")
            return render_template('update.html', entry=entry)
        if len(pwd) < 6:
            flash("Password must be at least 6 characters long", "error")
            return render_template('update.html', entry=entry)
        if ' ' in pwd:
            flash("Password cannot contain spaces", "error")
            return render_template('update.html', entry=entry)
        if not re.match(r'^[A-Za-z0-9!@#$%_+.\-]+$', pwd):
            flash("Password can only contain !@#$%_+.-, alphabets, and numbers", "error")
            logging.warning(f"Invalid password characters detected: {pwd}")
            return render_template('update.html', entry=entry)
        if new_entry_username != entry_username and PasswordEntry.query.filter_by(user_id=current_user.id, entry_username=new_entry_username).first():
            flash("Username already exists for this user", "error")
            return render_template('update.html', entry=entry)

        try:
            if new_entry_username != entry_username:
                db.session.delete(entry)
                enc_data = encryptor(new_entry_username, pwd)
                new_entry = PasswordEntry(purpose=purpose, user_id=current_user.id, entry_username=new_entry_username, data=enc_data)
                db.session.add(new_entry)
            else:
                entry.purpose = purpose
                entry.data = encryptor(new_entry_username, pwd)
            db.session.commit()
            flash("Entry updated successfully", "success")
            return redirect(url_for('home'))
        except Exception as e:
            logging.error(f"Error updating entry_username {entry_username} to {new_entry_username}: {e}")
            flash(f"Error updating entry: {e}", "error")
            return render_template('update.html', entry=entry)
    return render_template('update.html', entry=entry)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
