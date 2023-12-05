from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, get_flashed_messages
from flask_login import LoginManager, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
import re
from models import db, Users, Books, BookReviews, Genres, BookGenres, Followers, Bookshelves, BooksOnShelf, UserGenres

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:passwd@localhost/virtual_library'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '61ccdb6ea518090789595b34750d63b3'
app.config['SESSION_COOKIE_SECURE'] = True

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

def create_default_bookshelves(user_id):
    read_shelf = Bookshelves(shelf_name='Przeczytane', user_id=user_id)
    to_read_shelf = Bookshelves(shelf_name='Chcę przeczytać', user_id=user_id)
    reading_shelf = Bookshelves(shelf_name='Aktualnie czytam', user_id=user_id)

    db.session.add_all([read_shelf, to_read_shelf, reading_shelf])
    db.session.commit()

# Strona główna startowa
@app.route('/')
def index():
    genres = Genres.query.all()
    return render_template('index.html', genres=genres)

# Strona logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.passwd, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash('Nieprawidłowe dane logowania', 'error')
            return render_template('login.html', username='', password='', messages=get_flashed_messages())
    else:
        return render_template('login.html')
    
#Strona rejestracji
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_username = request.form['newUsername']
        new_email = request.form['newEmail']
        new_password = request.form['newPassword']

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', new_password):
            flash('Hasło musi zawierać co najmniej 8 znaków, jedną małą literę, jedną wielką literę, jedną cyfrę i jeden znak specjalny.', 'error')
            return render_template('register.html', messages=get_flashed_messages())

        existing_user = Users.query.filter_by(username=new_username).first()
        existing_email = Users.query.filter_by(email=new_email).first()
        
        if existing_user:
            flash('Podana nazwa użytkownika jest zajęta', 'error')
            return render_template('register.html', messages=get_flashed_messages())
        
        if existing_email:
            flash('Użytkownik z takim adresem email jest już zarejestrowany', 'error')
            return render_template('register.html', messages=get_flashed_messages())
        
        else:
            hashed_password = generate_password_hash(new_password)
            new_user = Users(username=new_username, email=new_email, passwd=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            create_default_bookshelves(new_user.user_id)
            session['username'] = new_username
            return redirect(url_for('home'))
    else:
        return render_template('register.html')
    
#Wylogowanie
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
    
#Strona główna po zalogowaniu
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = Users.query.filter_by(username=username).first()

    if request.method == 'POST':
        selected_genres = request.form.getlist('selected_genres')

        for genre_id in selected_genres:
            user_genre = UserGenres.query.filter_by(user_id=user.user_id, genre_id=genre_id).first()
            if not user_genre:
                user_favourite_genres = Genres.query.join(UserGenres).filter_by(user_id=user.user_id).all()
                if len(user_favourite_genres) < 5:
                    genre = Genres.query.get(int(genre_id))
                    if genre:
                        user_genre = UserGenres(user_id=user.user_id, genre_id=genre.genre_id)
                        db.session.add(user_genre)
                        db.session.commit()
                        user_favourite_genres.append(genre)
                    else:
                        flash('Nieprawidłowo wybrany gatunek.')
                else:
                    flash('Możesz wybrać maksymalnie 5 ulubionych gatunków.')
            else:
                flash('Ten gatunek jest już w ulubionych.')

    genres = Genres.query.all()
    user_favourite_genres = Genres.query.join(UserGenres).filter(UserGenres.user_id == user.user_id).all()

    return render_template('home.html', user=user, genres=genres, user_favourite_genres=user_favourite_genres, Books=Books, BookGenres=BookGenres)

#Profil użytkownika
@app.route('/user_profile')
def user_profile():
    if 'username' in session:
        username = session['username']
        user = Users.query.filter_by(username=username).first()
        user_bookshelves = Bookshelves.query.filter_by(user_id=user.user_id).all()
        return render_template('user_profile.html', user=user, user_bookshelves=user_bookshelves)
    
#Ustawienia
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = Users.query.filter_by(username=username).first()
    user_favourite_genres = Genres.query.join(UserGenres).filter(UserGenres.user_id == user.user_id).all()

    if request.method == 'POST':
        change_option = request.form.get('change_option')

        if change_option == 'change_username':
            new_username = request.form.get('new_username')
            existing_user = Users.query.filter(Users.user_id != user.user_id, Users.username == new_username).first()

            if existing_user:
                flash('Ta nazwa użytkownika jest już zajęta.', 'error')
            elif new_username == username:
                flash('Nowa nazwa użytkownika jest taka sama jak obecna.', 'error')
            else:
                user.username = new_username
                db.session.commit()
                session['username'] = new_username
                flash('Nazwa użytkownika została zmieniona pomyślnie!', 'success')
                user = Users.query.filter_by(username=new_username).first()

        elif change_option == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not check_password_hash(user.passwd, current_password):
                flash('Aktualne hasło jest nieprawidłowe.', 'error')
                return redirect(url_for('settings'))
            
            if new_password != confirm_password:
                flash('Nowe hasło i potwierdzenie hasła nie pasują do siebie.', 'error')
                return redirect(url_for('settings'))
            
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', new_password):
                flash('Nowe hasło musi zawierać co najmniej 8 znaków, jedną małą literę, jedną wielką literę, jedną cyfrę i jeden znak specjalny.', 'error')
                return redirect(url_for('settings'))

            user.passwd = generate_password_hash(new_password)

            db.session.commit()

            flash('Hasło zostało zmienione pomyślnie!', 'success')

        elif change_option == 'change_genres':
            current_genres = request.form.getlist('current_genres')

            UserGenres.query.filter_by(user_id=user.user_id).delete()

            for genre_id in current_genres:
                user_genre = UserGenres(user_id=user.user_id, genre_id=genre_id)
                db.session.add(user_genre)

            db.session.commit()

            user_favourite_genres = Genres.query.join(UserGenres).filter(UserGenres.user_id == user.user_id).all()

            flash('Ulubione gatunki zostały zmienione pomyślnie!', 'success')

        elif change_option == 'add_genres':
            added_genres = request.form.getlist('added_genres')

            if len(added_genres) > 5:
                flash('Możesz dodać maksymalnie 5 ulubionych gatunków.', 'error')
            else:
                current_favorite_genres_count = len(UserGenres.query.filter_by(user_id=user.user_id).all())
                if current_favorite_genres_count + len(added_genres) > 5:
                    flash('Możesz mieć maksymalnie 5 ulubionych gatunków.', 'error')
                else:
                    for genre_id in added_genres:
                        user_genre = UserGenres(user_id=user.user_id, genre_id=genre_id)
                        db.session.add(user_genre)

                    db.session.commit()

                user_favourite_genres = Genres.query.join(UserGenres).filter(UserGenres.user_id == user.user_id).all()

                flash('Ulubione gatunki zostały dodane pomyślnie!', 'success')

    genres = Genres.query.all()

    return render_template('settings.html', session=session, user=user, genres=genres, user_favourite_genres=user_favourite_genres)
    
@app.route('/remove_genre', methods=['POST'])
def remove_genre():
    if 'username' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    user = Users.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    genre_id = request.json.get('genreId')
    if not genre_id:
        return jsonify({'error': 'Genre ID not provided'}), 400

    UserGenres.query.filter_by(user_id=user.user_id, genre_id=genre_id).delete()
    db.session.commit()

    return jsonify({'success': True})


@app.route('/search_books', methods=['GET'])
def search_books():
    if 'username' not in session:
        return redirect(url_for('login'))

    search_query = request.args.get('search_query', '')

    books = Books.query.filter(or_(Books.title.ilike(f'%{search_query}%'), Books.author.ilike(f'%{search_query}%'))).all()

    return render_template('search_books.html', session=session, books=books, search_query=search_query)


@app.route('/book/<int:book_id>', methods=['GET'])
def book_details(book_id):
    book = Books.query.get(book_id)
    if not book:
        return render_template('book_not_found.html')
    
    username = session['username']
    user = Users.query.filter_by(username=username).first()
    genres = Genres.query.join(BookGenres).filter(BookGenres.book_id == book_id).all()

    user_bookshelves = Bookshelves.query.filter_by(user_id=user.user_id).all()

    return render_template('book_details.html', book=book, genres=genres, user_bookshelves=user_bookshelves)


@app.route('/add_to_shelf/<int:book_id>', methods=['POST'])
def add_to_shelf(book_id):

    username = session['username']
    user = Users.query.filter_by(username=username).first()
    shelf_id = request.form.get('shelf')  # Use 'shelf' instead of 'shelf_id'

    # Check if the shelf exists and belongs to the user
    user_bookshelves = Bookshelves.query.filter_by(user_id=user.user_id).all()
    if not user_bookshelves:
        flash('Nieprawidłowa półka.', 'error')
        return redirect(url_for('book_details', book_id=book_id))

    # Check if the book already exists on the shelf
    if BooksOnShelf.query.filter_by(shelf_id=shelf_id, book_id=book_id).first():
        flash('Książka już znajduje się na tej półce.', 'warning')
    else:
        book_on_shelf = BooksOnShelf(shelf_id=shelf_id, book_id=book_id)
        db.session.add(book_on_shelf)
        db.session.commit()
        flash('Książka została dodana na półkę.', 'success')

    return redirect(url_for('book_details', book_id=book_id))



@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)