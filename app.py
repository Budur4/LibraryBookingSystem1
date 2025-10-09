from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from models import db, User, Resource, Booking
from functools import wraps
from datetime import datetime, timedelta
import os
import re
import csv
from io import BytesIO
from reportlab.pdfgen import canvas
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'library.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'bodour_secret_key'

db.init_app(app)
with app.app_context():
    admin = User.query.filter_by(username="admin").first()
    if admin:
        if not admin.password_hash or admin.check_password("admin123") is False:
            admin.set_password("admin123")  
            db.session.commit()
            print("Admin password updated.")
        else:
            print("Admin password is correct, no changes needed.")
    else:
        admin = User(username="admin", email="admin@example.com", is_admin=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print("Admin created successfully.")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('⚠️ Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", email="admin@example.com", is_admin=True)
        admin.set_password("admin123")  # تأكد هنا يتم تعيين password_hash
        db.session.add(admin)
        db.session.commit()

@app.context_processor
def inject_session_user():
    uid = session.get('user_id')
    recommended = []
    if uid:
        u = User.query.get(uid)
        if u:
            past_bookings = Booking.query.filter_by(user_id=uid).all()
            booked_ids = [b.resource_id for b in past_bookings]
            types = {b.resource.type for b in past_bookings if b.resource}
            if types:
                recommended = Resource.query.filter(
                    Resource.type.in_(types),
                    ~Resource.id.in_(booked_ids)
                ).limit(5).all()
            return dict(
                logged_in=True,
                current_username=u.username,
                current_is_admin=u.is_admin,
                recommended_resources=recommended
            )
    return dict(logged_in=False, current_username=None, current_is_admin=False, recommended_resources=[])

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('resources_page'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not email or not password or not confirm_password:
            flash('❌ All fields are required!', 'danger')
            return redirect(url_for('register'))

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('❌ Invalid email format!', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('❌ Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('❌ This email is already registered!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('❌ Username already taken!', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, is_admin=False)
        new_user.set_password(password)  

        db.session.add(new_user)
        db.session.commit()

        flash('✅ Account created successfully! You can log in now.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('❌ Both email and password are required!', 'danger')
            return redirect(url_for('login'))

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('❌ Invalid email format!', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('❌ Email not registered.', 'danger')
            return redirect(url_for('login'))

        if not user.check_password(password):
            flash('❌ Incorrect password.', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session['username'] = user.username
        flash(f'✅ Welcome back, {user.username}!', 'success')
        return redirect(url_for('resources_page'))

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()

        if not email:
            flash('❌ Please enter your email address.', 'danger')
            return redirect(url_for('forgot_password'))

        if not user:
            flash('❌ This email is not registered.', 'danger')
            return redirect(url_for('forgot_password'))

        flash('✅ A reset link has been sent to your email.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_password = request.form.get('old_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not old_password or not new_password or not confirm_password:
            flash('❌ All fields are required!', 'danger')
            return redirect(url_for('change_password'))

        if not user.check_password(old_password):
            flash('❌ Incorrect current password.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('❌ Passwords do not match!', 'danger')
            return redirect(url_for('change_password'))

        user.set_password(new_password)
        db.session.commit()
        flash('✅ Password changed successfully!', 'success')
        return redirect(url_for('resources_page'))

    return render_template('change_password.html')

@app.route("/resources")
@login_required
def resources_page():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("login"))

    current_user = User.query.get(user_id)

    resources = Resource.query.all()

    my_bookings = Booking.query.filter_by(user_id=user_id).all()

    booked_resource_ids = [b.resource_id for b in my_bookings]

    return render_template(
        "resources.html",
        resources=resources,
        my_bookings=my_bookings,
        booked_resource_ids=booked_resource_ids,
        current_is_admin=current_user.is_admin,
        all_bookings=Booking.query.all()
    )

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    u = User.query.get(session['user_id'])
    if not u.is_admin:
        flash('⚠️ You are not authorized.', 'danger')
        return redirect(url_for('resources_page'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        type_ = request.form['type'].strip()
        desc = request.form['description'].strip()
        capacity = request.form['capacity']
        if not title or not type_:
            flash('❌ Title and Type are required!', 'danger')
        else:
            new_r = Resource(title=title, type=type_, description=desc, capacity=capacity)
            db.session.add(new_r)
            db.session.commit()
            flash(f'✅ Resource "{title}" added!', 'success')
        return redirect(url_for('admin_panel'))

    users = User.query.all()
    resources = Resource.query.all()
    bookings = Booking.query.order_by(Booking.start_time.desc()).all()
    return render_template('admin.html', users=users, resources=resources, bookings=bookings)

@app.route('/resource/book/<int:resource_id>', methods=['POST'])
@login_required
def book_resource(resource_id):
    user = User.query.get(session['user_id'])
    resource = Resource.query.get_or_404(resource_id)
    now = datetime.now()
    end_time = now + timedelta(hours=1)

    booking = Booking(user_id=user.id, resource_id=resource.id, start_time=now, end_time=end_time)
    db.session.add(booking)
    db.session.commit()
    flash(f'✅ "{resource.title}" booked successfully!', 'success')
    return redirect(url_for('resources_page'))

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != session['user_id']:
        flash('⚠️ Not authorized to cancel this booking.', 'danger')
    else:
        db.session.delete(b)
        db.session.commit()
        flash('✅ Booking canceled.', 'success')
    return redirect(url_for('resources_page'))

@app.route('/admin/resource/delete/<int:resource_id>', methods=['POST'])
@login_required
def admin_delete_resource(resource_id):
    u = User.query.get(session['user_id'])
    if not u.is_admin:
        flash('⚠️ Unauthorized.', 'danger')
        return redirect(url_for('resources_page'))
    r = Resource.query.get_or_404(resource_id)
    db.session.delete(r)
    db.session.commit()
    flash(f'✅ Resource "{r.title}" deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    admin_user = User.query.get(session['user_id'])
    if not admin_user.is_admin:
        flash('⚠️ Only admin can delete users.', 'danger')
        return redirect(url_for('resources_page'))

    user = User.query.get(user_id)
    if not user:
        flash('❌ User not found.', 'danger')
        return redirect(url_for('admin_panel'))

    if user.is_admin:
        flash('⚠️ You cannot delete another admin.', 'warning')
        return redirect(url_for('admin_panel'))

    Booking.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()

    flash(f'✅ User "{user.username}" deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/export/csv')
@login_required
def export_csv():
    bookings = Booking.query.all()
    si = BytesIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'User', 'Resource', 'Start', 'End'])
    for b in bookings:
        cw.writerow([b.id, b.user.username, b.resource.title, b.start_time, b.end_time])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=bookings.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/export/pdf')
@login_required
def export_pdf():
    bookings = Booking.query.order_by(Booking.start_time.desc()).all()
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    y = 800
    p.setFont("Helvetica", 12)
    p.drawString(50, y, "Bookings Report")
    y -= 30
    for b in bookings:
        line = f"{b.id} | {b.user.username} | {b.resource.title} | {b.start_time} | {b.end_time}"
        p.drawString(50, y, line)
        y -= 20
        if y < 50:
            p.showPage()
            y = 800
    p.save()
    buffer.seek(0)
    return make_response(buffer.read(), 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename=bookings.pdf'
    })


if __name__ == "__main__":
    app.run(debug=True)