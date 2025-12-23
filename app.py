import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_12345') 

DATABASE = 'finance_tracker.db'

# --- DATABASE HELPERS ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # Tables Setup
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            account_name TEXT NOT NULL, amount REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, allocated_amount REAL DEFAULT 0.0, spent_amount REAL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL, balance_id INTEGER NOT NULL,
            description TEXT, amount REAL NOT NULL, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories (id), FOREIGN KEY (balance_id) REFERENCES balances (id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS debts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER NOT NULL,
            person_name TEXT NOT NULL, 
            amount REAL NOT NULL, 
            type TEXT NOT NULL, 
            status TEXT DEFAULT 'pending',
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Seed Admin
        admin = db.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            db.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', 
                         ('admin', generate_password_hash('admin123'), 1))
        db.commit()

# --- AUTH DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---
@app.route('/')
@login_required
def index():
    db = get_db()
    uid = session['user_id']
    
    balances = db.execute('SELECT * FROM balances WHERE user_id = ?', (uid,)).fetchall()
    categories = db.execute('SELECT * FROM categories WHERE user_id = ?', (uid,)).fetchall()
    expenses = db.execute('SELECT e.*, c.name as cat_name FROM expenses e JOIN categories c ON e.category_id = c.id WHERE e.user_id = ? ORDER BY date DESC LIMIT 10', (uid,)).fetchall()
    monthly_stats = db.execute("SELECT strftime('%m-%Y', date) as month, SUM(amount) as total FROM expenses WHERE user_id = ? GROUP BY month ORDER BY date DESC", (uid,)).fetchall()

    # 1. ACTUAL CASH: Money physically in your accounts.
    # When you borrow 100, your 'balances' table already increases by 100 in the add_debt route.
    cash_in_hand = sum(b['amount'] for b in balances)
    
    # 2. DEBT STATUS: Borrowed = (+), Lent = (-)
    debts_list = db.execute('SELECT amount FROM debts WHERE user_id = ?', (uid,)).fetchall()
    net_debt_balance = sum(d['amount'] for d in debts_list)
    
    # 3. NET WORTH LOGIC: 
    # To prevent doubling, Net Worth should simply be your Cash in Hand.
    # Why? Because when you borrowed 100, your cash went up by 100. 
    # If you want Net Worth to show your "Total Buying Power," it is your Cash.
    total_balance = cash_in_hand
    
    # 4. FREE TO USE: Cash minus what you've promised to your budget categories.
    # When you borrow money, your cash increases, so this value naturally increases.
    budget_reserved = sum(c['allocated_amount'] - c['spent_amount'] for c in categories)
    unallocated = cash_in_hand - budget_reserved
    
    debts = db.execute('SELECT * FROM debts WHERE user_id = ? AND amount != 0', (uid,)).fetchall()
    return render_template('dashboard.html', **locals())

@app.route('/add_balance', methods=['GET', 'POST'])
@login_required
def add_balance():
    db = get_db()
    uid = session['user_id']
    if request.method == 'POST':
        db.execute('INSERT INTO balances (user_id, account_name, amount) VALUES (?, ?, ?)',
                     (uid, request.form['account_name'], float(request.form['amount'])))
        db.commit()
        return redirect(url_for('add_balance'))
    
    balances = db.execute('SELECT * FROM balances WHERE user_id = ?', (uid,)).fetchall()
    return render_template('add_balance.html', balances=balances)


# --- EDIT ACCOUNT BALANCE ---
@app.route('/edit_balance/<int:id>', methods=['POST'])
@login_required
def edit_balance(id):
    db = get_db()
    uid = session['user_id']
    new_amount = request.form.get('amount')
    new_name = request.form.get('account_name')
    
    # Update the specific account belonging to the logged-in user
    db.execute('UPDATE balances SET amount = ?, account_name = ? WHERE id = ? AND user_id = ?', 
               (float(new_amount), new_name, id, uid))
    db.commit()
    flash("Account updated successfully!")
    return redirect(url_for('add_balance'))

# --- DELETE ACCOUNT ---
@app.route('/delete_balance/<int:id>', methods=['POST'])
@login_required
def delete_balance(id):
    db = get_db()
    uid = session['user_id']
    
    # Delete the account only if it belongs to the current user
    db.execute('DELETE FROM balances WHERE id = ? AND user_id = ?', (id, uid))
    db.commit()
    flash("Account deleted.")
    return redirect(url_for('add_balance'))

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    db = get_db()
    uid = session['user_id']
    if request.method == 'POST':
        try:
            amt = float(request.form['amount'])
            db.execute('UPDATE balances SET amount = amount - ? WHERE id = ?', (amt, request.form['balance_id']))
            db.execute('UPDATE categories SET spent_amount = spent_amount + ? WHERE id = ?', (amt, request.form['category_id']))
            db.execute('INSERT INTO expenses (user_id, category_id, balance_id, description, amount) VALUES (?,?,?,?,?)',
                         (uid, request.form['category_id'], request.form['balance_id'], request.form['description'], amt))
            db.commit()
            return redirect(url_for('index'))
        except Exception as e:
            flash("Error processing expense.")
            
    cats = db.execute('SELECT * FROM categories WHERE user_id = ?', (uid,)).fetchall()
    bals = db.execute('SELECT * FROM balances WHERE user_id = ?', (uid,)).fetchall()
    return render_template('add_expense.html', categories=cats, balances=bals)

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    db = get_db()
    uid = session['user_id']
    if request.method == 'POST':
        db.execute('INSERT INTO categories (user_id, name, allocated_amount) VALUES (?, ?, ?)',
                     (uid, request.form['name'], float(request.form['amount'])))
        db.commit()
        return redirect(url_for('add_category'))
    
    categories = db.execute('SELECT * FROM categories WHERE user_id = ?', (uid,)).fetchall()
    return render_template('add_category.html', categories=categories)


# --- EDIT CATEGORY ---
@app.route('/edit_category/<int:id>', methods=['POST'])
@login_required
def edit_category(id):
    db = get_db()
    uid = session['user_id']
    new_name = request.form.get('name')
    new_allocation = request.form.get('amount')
    
    # Update category only if it belongs to the logged-in user
    db.execute('UPDATE categories SET name = ?, allocated_amount = ? WHERE id = ? AND user_id = ?', 
               (new_name, float(new_allocation), id, uid))
    db.commit()
    flash("Category updated!")
    return redirect(url_for('add_category'))

# --- DELETE CATEGORY ---
@app.route('/delete_category/<int:id>', methods=['POST'])
@login_required
def delete_category(id):
    db = get_db()
    uid = session['user_id']
    
    # Warning: Deleting a category might leave expenses "orphaned" 
    # unless you delete them or reassign them. 
    db.execute('DELETE FROM categories WHERE id = ? AND user_id = ?', (id, uid))
    db.commit()
    flash("Category deleted.")
    return redirect(url_for('add_category'))



@app.route('/add_debt', methods=['GET', 'POST'])
@login_required
def add_debt():
    db = get_db()
    uid = session['user_id']
    
    if request.method == 'POST':
        person = request.form['person_name'].strip()
        amount = float(request.form['amount'])
        action = request.form['type'] 
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 1. Update Account Balance
        first_balance = db.execute('SELECT id FROM balances WHERE user_id = ? LIMIT 1', (uid,)).fetchone()
        if first_balance:
            if action == 'borrow':
                db.execute('UPDATE balances SET amount = amount + ? WHERE id = ?', (amount, first_balance['id']))
            else:
                db.execute('UPDATE balances SET amount = amount - ? WHERE id = ?', (amount, first_balance['id']))

        # 2. Update Debt Record (Aggregate)
        change = amount if action == 'borrow' else -amount
        existing = db.execute('SELECT id, amount FROM debts WHERE user_id = ? AND person_name = ? COLLATE NOCASE', 
                             (uid, person)).fetchone()
        
        if existing:
            db.execute('UPDATE debts SET amount = amount + ?, date = ? WHERE id = ?', 
                         (change, now, existing['id']))
        else:
            db.execute('INSERT INTO debts (user_id, person_name, amount, type, date) VALUES (?, ?, ?, ?, ?)',
                         (uid, person, change, action, now))
        
        db.commit()
        return redirect(url_for('add_debt'))
    
    debts = db.execute('SELECT * FROM debts WHERE user_id = ? AND amount != 0 ORDER BY date DESC', (uid,)).fetchall()
    return render_template('add_debt.html', debts=debts)

@app.route('/settle_debt/<int:debt_id>', methods=['POST'])
@login_required
def settle_debt(debt_id):
    db = get_db()
    uid = session['user_id']
    debt = db.execute('SELECT * FROM debts WHERE id = ? AND user_id = ?', (debt_id, uid)).fetchone()
    
    if debt:
        amount = debt['amount']
        account = db.execute('SELECT id FROM balances WHERE user_id = ? LIMIT 1', (uid,)).fetchone()
        
        if account:
            # Reverse the debt effect on bank balance
            # Paying back borrowed (amt > 0) -> Subtract from cash
            # Receiving lent (amt < 0) -> Add to cash
            db.execute('UPDATE balances SET amount = amount - ? WHERE id = ?', (amount, account['id']))
        
        db.execute('DELETE FROM debts WHERE id = ?', (debt_id,))
        db.commit()
        flash("Debt settled!")
        
    return redirect(url_for('add_debt'))

@app.route('/tracking')
@login_required
def tracking():
    db = get_db()
    uid = session['user_id']
    years = db.execute("SELECT DISTINCT strftime('%Y', date) as year FROM expenses WHERE user_id = ? ORDER BY year DESC", (uid,)).fetchall()
    months = db.execute("SELECT DISTINCT strftime('%m-%Y', date) as month_id FROM expenses WHERE user_id = ? ORDER BY date DESC", (uid,)).fetchall()
    all_debts = db.execute("SELECT * FROM debts WHERE user_id = ? ORDER BY date DESC", (uid,)).fetchall()
    return render_template('tracking.html', years=years, months=months, all_debts=all_debts)

@app.route('/tracking/year/<int:year>')
@login_required
def year_detail(year):
    db = get_db()
    uid = session['user_id']
    expenses = db.execute("SELECT * FROM expenses WHERE user_id = ? AND strftime('%Y', date) = ? ORDER BY date DESC", (uid, str(year))).fetchall()
    total = sum(e['amount'] for e in expenses)
    return render_template('detail_view.html', title=f"Year {year}", expenses=expenses, total=total)

@app.route('/tracking/month/<month_id>')
@login_required
def month_detail(month_id):
    db = get_db()
    uid = session['user_id']
    expenses = db.execute("SELECT * FROM expenses WHERE user_id = ? AND strftime('%m-%Y', date) = ? ORDER BY date DESC", (uid, month_id)).fetchall()
    total = sum(e['amount'] for e in expenses)
    return render_template('detail_view.html', title=month_id, month_id=month_id, expenses=expenses, total=total)



# --- ADMIN: ADD USER ---
@app.route('/manage/create-user', methods=['GET', 'POST'])
@login_required
def add_user():
    # Security Check: Only admins can access this route
    if not session.get('is_admin'):
        flash("Unauthorized access.")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        db = get_db()
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 1 if request.form.get('is_admin') else 0
        
        try:
            db.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                       (username, generate_password_hash(password), is_admin))
            db.commit()
            flash(f"User '{username}' created successfully!")
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError:
            flash("Error: Username already exists.")
            
    return render_template('add_user.html')

# Ensure your admin dashboard route exists as well
@app.route('/system-control')
@login_required
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    db = get_db()
    users = db.execute('SELECT id, username, is_admin FROM users').fetchall()
    return render_template('admin_dashboard.html', users=users)


@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    db = get_db()
    new_username = request.form.get('username')
    new_password = request.form.get('password')
    is_admin = 1 if request.form.get('is_admin') else 0

    if new_password: # Only update password if a new one is provided
        hashed_pw = generate_password_hash(new_password)
        db.execute('UPDATE users SET username = ?, password = ?, is_admin = ? WHERE id = ?', 
                   (new_username, hashed_pw, is_admin, user_id))
    else:
        db.execute('UPDATE users SET username = ?, is_admin = ? WHERE id = ?', 
                   (new_username, is_admin, user_id))
    
    db.commit()
    flash("User updated successfully!")
    return redirect(url_for('admin_dashboard'))

# --- ADMIN: DELETE USER ---
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    # Prevent admin from deleting themselves
    if user_id == session['user_id']:
        flash("You cannot delete your own admin account!")
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash("User deleted.")
    return redirect(url_for('admin_dashboard'))

@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
        
        if user and check_password_hash(user['password'], request.form['password']):
            # Store data in session
            session.update({
                'user_id': user['id'], 
                'username': user['username'], 
                'is_admin': user['is_admin']
            })
            
            # --- ADD THIS LOGIC HERE ---
            if user['is_admin'] == 1:
                return redirect(url_for('admin_dashboard')) # Redirect Admin to Admin Panel
            else:
                return redirect(url_for('index')) # Redirect Normal User to Dashboard
            # ---------------------------
            
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # Get port from environment variable or default to 5000
    port = int(os.environ.get("PORT", 5222))
    app.run(host='0.0.0.0', port=port)