from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from encdec import encryptor, decryptor
import logging
import re

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)

class PasswordEntry(db.Model):
    purpose = db.Column(db.String(100))
    user_id = db.Column(db.Text, primary_key=True)
    data = db.Column(db.Text)

with app.app_context():
    db.create_all()

@app.errorhandler(404)
def page_not_found(e):
    logging.error(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        purpose = request.form['Purpose'].strip()
        uid = request.form['Username'].strip()
        pwd = request.form['Password'].strip()

        if not purpose or not uid or not pwd:
            flash("All fields are required", "error")
            return redirect('/')
        if not re.match(r'^[a-zA-Z0-9_@.]+$', uid):
            flash("Invalid username: Use only letters, numbers, underscores, @, or .", "error")
            return redirect('/')
        if len(pwd) < 6:
            flash("Password must be at least 6 characters long", "error")
            return redirect('/')
        if ' ' in pwd:
            flash("Password cannot contain spaces", "error")
            return redirect('/')
        if not re.match(r'^[A-Za-z0-9!@#$%&_+.\-]+$', pwd):
            flash("Password can only contain !@#$%&_+.-, alphabets, and numbers", "error")
            logging.warning(f"Invalid password characters detected: {pwd}")
            return redirect('/')
        if PasswordEntry.query.get(uid):
            flash("Username already exists", "error")
            return redirect('/')

        enc_data = encryptor(uid, pwd)
        new_entry = PasswordEntry(purpose=purpose, user_id=uid, data=enc_data)
        try:
            db.session.add(new_entry)
            db.session.commit()
            flash("Entry added successfully", "success")
        except Exception as e:
            logging.error(f"Error adding entry {uid}: {e}")
            flash(f"Error saving entry: {e}", "error")
        return redirect('/')
    else:
        entries = PasswordEntry.query.all()
        datalist = []
        for e in entries:
            try:
                dec = decryptor(e.data)
                if not re.match(r'^[A-Za-z0-9!@#$%&_+.\-]+$', dec[1]):
                    logging.warning(f"Invalid characters in decrypted password for user_id {e.user_id}: {dec[1]}")
                    datalist.append([e.purpose, e.user_id, "Invalid password characters"])
                else:
                    datalist.append([e.purpose, e.user_id, dec[1]])
            except Exception as e:
                logging.error(f"Error decrypting for user_id {e.user_id}: {e}")
                datalist.append([e.purpose, e.user_id, "Decryption failed"])
        return render_template('index.html', datalist=datalist)

@app.route('/delete/<string:user_id>')
def delete(user_id):
    if not user_id:
        logging.error("Empty user_id in delete route")
        abort(404)
    del_cred = PasswordEntry.query.get_or_404(user_id)
    try:
        db.session.delete(del_cred)
        db.session.commit()
        flash(f"Deleted entry for {user_id}", "success")
        return redirect(url_for('home'))
    except Exception as e:
        logging.error(f"Error deleting user_id {user_id}: {e}")
        flash(f"Error deleting entry: {e}", "error")
        return redirect(url_for('home'))

@app.route('/update/<string:user_id>', methods=['GET', 'POST'])
def update(user_id):
    entry = PasswordEntry.query.get_or_404(user_id)
    if request.method == 'POST':
        purpose = request.form['Purpose'].strip()
        new_user_id = request.form['Username'].strip()
        pwd = request.form['Password'].strip()

        if not purpose or not new_user_id or not pwd:
            flash("All fields are required", "error")
            return render_template('update.html', entry=entry)
        if not re.match(r'^[a-zA-Z0-9_@.]+$', new_user_id):
            flash("Invalid username: Use only letters, numbers, underscores, @, or .", "error")
            return render_template('update.html', entry=entry)
        if len(pwd) < 6:
            flash("Password must be at least 6 characters long", "error")
            return render_template('update.html', entry=entry)
        if ' ' in pwd:
            flash("Password cannot contain spaces", "error")
            return render_template('update.html', entry=entry)
        if not re.match(r'^[A-Za-z0-9!@#$%&_+.\-]+$', pwd):
            flash("Password can only contain !@#$%&_+.-, alphabets, and numbers", "error")
            logging.warning(f"Invalid password characters detected: {pwd}")
            return render_template('update.html', entry=entry)
        if new_user_id != user_id and PasswordEntry.query.get(new_user_id):
            flash("Username already exists", "error")
            return render_template('update.html', entry=entry)

        try:
            if new_user_id != user_id:
                db.session.delete(entry)
                enc_data = encryptor(new_user_id, pwd)
                new_entry = PasswordEntry(purpose=purpose, user_id=new_user_id, data=enc_data)
                db.session.add(new_entry)
            else:
                entry.purpose = purpose
                entry.data = encryptor(new_user_id, pwd)
            db.session.commit()
            flash("Entry updated successfully", "success")
            return redirect(url_for('home'))
        except Exception as e:
            logging.error(f"Error updating user_id {user_id} to {new_user_id}: {e}")
            flash(f"Error updating entry: {e}", "error")
            return render_template('update.html', entry=entry)
    return render_template('update.html', entry=entry)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
