from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key'

DATABASE = 'database.db'

# Функция для подключения к базе данных
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Инициализация базы данных
def init_db():
    with get_db() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS initiatives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            author_id INTEGER,
            FOREIGN KEY(author_id) REFERENCES users(id)
        );
                         
        CREATE TABLE IF NOT EXISTS votes (
            user_id INTEGER,
            initiative_id INTEGER,
            vote_type TEXT CHECK(vote_type IN ('up', 'down')),
            PRIMARY KEY (user_id, initiative_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (initiative_id) REFERENCES initiatives(id)
        );                                  
        ''')
init_db()

# Главная страница с инициативами
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    limit = 20
    offset = (page - 1) * limit

    initiatives = get_db().execute("""
        SELECT initiatives.id, initiatives.title, initiatives.content, initiatives.created_at, 
               users.username, initiatives.author_id
        FROM initiatives
        LEFT JOIN users ON initiatives.author_id = users.id
        ORDER BY initiatives.created_at DESC
        LIMIT ? OFFSET ?
    """, (limit, offset)).fetchall()

    initiatives_with_votes = []
    for initiative in initiatives:
        initiative_id = initiative['id']

        up_votes = get_db().execute("""
            SELECT COUNT(*) FROM votes WHERE initiative_id = ? AND vote_type = 'up'
        """, (initiative_id,)).fetchone()[0]

        down_votes = get_db().execute("""
            SELECT COUNT(*) FROM votes WHERE initiative_id = ? AND vote_type = 'down'
        """, (initiative_id,)).fetchone()[0]

        initiative_with_votes = {
            **initiative,
            'up_votes': up_votes,
            'down_votes': down_votes,
            'total_votes': up_votes - down_votes
        }

        initiatives_with_votes.append(initiative_with_votes)

    total_initiatives = get_db().execute("""
        SELECT COUNT(*) FROM initiatives
    """).fetchone()[0]

    has_more = total_initiatives > page * limit

    return render_template('index.html', initiatives=initiatives_with_votes, page=page, has_more=has_more, get_db=get_db)

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        with get_db() as db:
            try:
                db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                db.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Такое имя пользователя уже существует.', 'danger')
    
    return render_template('register.html')

# Авторизация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                return redirect(url_for('index'))
            else:
                flash('Неверное имя пользователя или пароль.', 'danger')
    
    return render_template('login.html')

# Выход
@app.route('/logout', methods=['POST'])
def logout():
    session.clear() 
    return redirect(url_for('index'))

# Добавление инициативы
@app.route('/new', methods=['GET', 'POST'])
def new_initiative():
    if 'user_id' not in session:
        flash('Войдите в систему для добавления инициатив.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        with get_db() as db:
            db.execute('INSERT INTO initiatives (title, content, author_id) VALUES (?, ?, ?)',
                       (title, content, session['user_id']))
            db.commit()  
            return redirect(url_for('index'))
    
    return render_template('new_initiative.html')

# Удаление инициативы
@app.route('/delete/<int:id>')
def delete_initiative(id):
    with get_db() as db:
        initiative = db.execute('SELECT * FROM initiatives WHERE id = ?', (id,)).fetchone()
        if not initiative:
            flash('Инициатива не найдена.', 'danger')
        elif initiative['author_id'] == session.get('user_id') or session.get('is_admin'):
            db.execute('DELETE FROM initiatives WHERE id = ?', (id,))
            db.commit()
        else:
            flash('У вас нет прав для удаления этой инициативы.', 'danger')
    
    return redirect(url_for('index'))

# Голосование
@app.route('/vote/<int:id>/<vote_type>')
def vote(id, vote_type):
    if session.get('user_id') is None:
        return redirect(url_for('login'))  

    user_id = session['user_id']
    
    # Проверяем, проголосовал ли пользователь уже
    with get_db() as db:
        existing_vote = db.execute(""" 
            SELECT vote_type FROM votes WHERE user_id = ? AND initiative_id = ?
        """, (user_id, id)).fetchone()

        if existing_vote:
            # Если голос уже есть, обновляем его
            if existing_vote['vote_type'] == vote_type:
                # Если пользователь поставил тот же голос (лайк/дизлайк), то удаляем его 
                db.execute("""
                    DELETE FROM votes WHERE user_id = ? AND initiative_id = ?
                """, (user_id, id))
            else:
                # Если голос другой, меняем его
                db.execute("""
                    UPDATE votes SET vote_type = ? WHERE user_id = ? AND initiative_id = ?
                """, (vote_type, user_id, id))
        else:
            # Если голос еще не поставлен, добавляем его
            db.execute("""
                INSERT INTO votes (user_id, initiative_id, vote_type) VALUES (?, ?, ?)
            """, (user_id, id, vote_type))

        # Обновляем количество голосов для инициативы
        if vote_type == 'up':
            db.execute("""
                UPDATE initiatives SET votes = votes + 1 WHERE id = ?
            """, (id,))
        elif vote_type == 'down':
            db.execute("""
                UPDATE initiatives SET votes = votes - 1 WHERE id = ?
            """, (id,))

        db.commit()  # После выполнения всех операций с базой данных

    return redirect(url_for('index'))

# Админ-панель
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if not session.get('is_admin'):
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        with get_db() as db:
            # Проверяем, что отправлена форма удаления пользователя
            if 'delete_user' in request.form:
                user_id = request.form['delete_user']
                db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            
            # Проверяем, что отправлена форма удаления инициативы
            elif 'delete_initiative' in request.form:
                initiative_id = request.form['delete_initiative']
                db.execute('DELETE FROM initiatives WHERE id = ?', (initiative_id,))

            db.commit()

        return redirect(url_for('admin_panel'))

    # Для GET-запроса отображаем админ-панель
    with get_db() as db:
        users = db.execute('SELECT * FROM users').fetchall()
        initiatives = db.execute('SELECT * FROM initiatives').fetchall()

    return render_template('admin_panel.html', users=users, initiatives=initiatives)