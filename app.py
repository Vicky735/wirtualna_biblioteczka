from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, get_flashed_messages, send_from_directory
from flask_login import LoginManager, logout_user
from sqlalchemy import or_, func
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, validators, SelectField
from wtforms.validators import DataRequired, EqualTo, Length, Email, Regexp
import re
from datetime import datetime, timedelta, timezone
from models import db, Users, Books, BookReviews, BookRatings, Genres, BookGenres, Bookshelves, BooksOnShelf, UserGenres

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:passwd@localhost/virtual_library'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '61ccdb6ea518090789595b34750d63b3'
app.config['SESSION_COOKIE_SECURE'] = True

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class LoginForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj')

class RegistrationForm(FlaskForm):
    newUsername = StringField('Nazwa użytkownika', validators=[DataRequired()])
    newEmail = StringField('Email', validators=[DataRequired(), Email(message="Nieprawidłowy adres email")])
    newPassword = PasswordField('Hasło', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
            message="Hasło musi zawierać co najmniej 8 liter, jedną wielką literę, jedną cyfrę i jeden znak specjalny."
        )
    ])
    confirmPassword = PasswordField("Powtórz hasło", validators=[
        DataRequired(),
        EqualTo('newPassword', message="Hasła muszą się zgadzać.")])
    submit = SubmitField('Zarejestruj')

class ChangeUsernameForm(FlaskForm):
    new_username = StringField('Nazwa użytkownika', validators=[DataRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Obecne hasło', validators=[DataRequired()])
    new_password = PasswordField('Nowe hasło', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
            message="Hasło musi zawierać co najmniej 8 liter, jedną wielką literę, jedną cyfrę i jeden znak specjalny."
        )
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Hasła muszą się zgadzać')
    ])


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
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.passwd, password):
            session['username'] = username
            session['login_attempts'] = {}
            return redirect(url_for('home'))
        else:
            login_attempts = session.setdefault('login_attempts', {})
            login_attempts.setdefault(username, 0)

            last_attempt_times = session.setdefault('last_attempt_times', {})
            last_attempt_time = last_attempt_times.get(username)
            utc = timezone.utc
            current_time = datetime.utcnow().replace(tzinfo=utc)

            if (
                last_attempt_time
                and current_time - last_attempt_time < timedelta(minutes=1)
            ):
                flash('Przekroczono limit prób logowania. Spróbuj ponownie później.', 'error')
                return redirect(url_for('ratelimit_exceeded'))
            session['last_attempt_time'] = current_time
            session['login_attempts'][username] += 1
            if session['login_attempts'][username] >= 5:
                return redirect(url_for('ratelimit_exceeded'))
            flash('Nieprawidłowe dane logowania', 'error')
            return render_template('login.html', messages=get_flashed_messages(), form=form)
    else:
        return render_template('login.html', form=form)
    
@app.route('/ratelimit_exceeded')
def ratelimit_exceeded():
    return render_template('ratelimit_exceeded.html')
    
#Strona rejestracji
@app.route('/register', methods=['GET', 'POST']) 
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        new_username = form.newUsername.data
        new_email = form.newEmail.data
        new_password = form.newPassword.data

        existing_user = Users.query.filter_by(username=new_username).first()
        existing_email = Users.query.filter_by(email=new_email).first()
        
        if existing_user:
            flash('Podana nazwa użytkownika jest już zajęta', 'error')
            return render_template('register.html', messages=get_flashed_messages(), form=form)
        
        if existing_email:
            flash('Użytkownik z takim adresem email jest już zarejestrowany', 'error')
            return render_template('register.html', messages=get_flashed_messages(), form=form)
        
        else:
            hashed_password = generate_password_hash(new_password)
            new_user = Users(username=new_username, email=new_email, passwd=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            create_default_bookshelves(new_user.user_id)
            session['username'] = new_username
            return redirect(url_for('home'))
    else:
        return render_template('register.html', form=form)
    
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
        return render_template('user_profile.html', user=user, user_bookshelves=user_bookshelves, Books=Books)
    
#Ustawienia
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    change_username_form = ChangeUsernameForm()
    change_password_form = ChangePasswordForm()

    username = session['username']
    user = Users.query.filter_by(username=username).first()
    user_favourite_genres = Genres.query.join(UserGenres).filter(UserGenres.user_id == user.user_id).all()

    if request.method == 'POST':
        change_option = request.form.get('change_option')

        if change_option == 'change_username' and change_username_form.validate_on_submit():
            new_username = change_username_form.new_username.data
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

        elif change_option == 'change_password' and change_password_form.validate_on_submit():
            current_password = change_password_form.current_password.data
            new_password = change_password_form.new_password.data

            if not check_password_hash(user.passwd, current_password):
                flash('Aktualne hasło jest nieprawidłowe.', 'error')
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

        elif change_option == 'add_genres':
            added_genres = request.form.getlist('added_genres')

            if len(added_genres) > 5:
                pass
            else:
                current_favorite_genres_ids = [str(genre.genre_id) for genre in user_favourite_genres]
                current_favorite_genres_count = len(current_favorite_genres_ids)

                if current_favorite_genres_count + len(added_genres) > 5:
                    pass
                else:
                    for genre_id in added_genres:
                        if genre_id not in current_favorite_genres_ids:
                            user_genre = UserGenres(user_id=user.user_id, genre_id=genre_id)
                            db.session.add(user_genre)

                    db.session.commit()

                user_favourite_genres = Genres.query.join(UserGenres).filter(UserGenres.user_id == user.user_id).all()

    genres = Genres.query.all()

    return render_template('settings.html', session=session, user=user, genres=genres, 
                           user_favourite_genres=user_favourite_genres, change_username_form=change_username_form,
                           change_password_form=change_password_form)


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
    
    user_genre = UserGenres.query.filter_by(user_id=user.user_id, genre_id=genre_id).first()
    if not user_genre:
        return jsonify({'error': 'Genre not found in user favorites'}), 404

    db.session.delete(user_genre)
    db.session.commit()

    return jsonify({'success': True})


@app.route('/search_books', methods=['GET'])
def search_books():
    if 'username' not in session:
        return redirect(url_for('login'))

    search_query = request.args.get('search_query', '')

    books = Books.query.filter(or_(
        func.lower(Books.title).ilike(func.lower(f'%{search_query}%')),
        func.lower(Books.author).ilike(func.lower(f'%{search_query}%'))
    )).all()

    return render_template('search_books.html', session=session, books=books, search_query=search_query)


@app.route('/book/<int:book_id>', methods=['GET'])
def book_details(book_id):
    book = db.session.query(Books).get(book_id)
    
    username = session['username']
    user = Users.query.filter_by(username=username).first()
    genres = Genres.query.join(BookGenres).filter(BookGenres.book_id == book_id).all()
    user_ratings = BookRatings.query.filter_by(book_id=book_id, user_id=user.user_id).first()
    all_reviews = BookReviews.query.filter_by(book_id=book_id).all()
    user_bookshelves = Bookshelves.query.filter_by(user_id=user.user_id).all()

    return render_template('book_details.html', book=book, genres=genres, 
                           user_bookshelves=user_bookshelves, user_ratings=user_ratings,
                           all_reviews=all_reviews)


@app.route('/add_to_shelf/<int:book_id>', methods=['POST'])
def add_to_shelf(book_id):

    username = session['username']
    user = Users.query.filter_by(username=username).first()
    
    shelf_id = request.form.get('shelf')

    user_bookshelves = Bookshelves.query.filter_by(user_id=user.user_id).all()
    if not user_bookshelves:
        flash('Nieprawidłowa półka.', 'error')
        return redirect(url_for('book_details', book_id=book_id))

    if BooksOnShelf.query.filter_by(shelf_id=shelf_id, book_id=book_id).first():
        flash('Książka już znajduje się na tej półce.', 'warning')
    else:
        book_on_shelf = BooksOnShelf(shelf_id=shelf_id, book_id=book_id)
        db.session.add(book_on_shelf)
        db.session.commit()
        flash('Książka została dodana na półkę.', 'success')

    return redirect(url_for('book_details', book_id=book_id))


@app.route('/add_review/<int:book_id>', methods=['POST'])
def add_review(book_id):
    username = session['username']
    user = Users.query.filter_by(username=username).first()

    review_text = request.form.get('review')

    try:
        existing_review = BookReviews.query.filter_by(book_id=book_id, user_id=user.user_id).first()

        if existing_review:
            existing_review.review = review_text
            db.session.commit()
            flash('Recenzja została zaktualizowana.', 'success')
        else:
            new_review = BookReviews(book_id=book_id, user_id=user.user_id, review=review_text)
            db.session.add(new_review)
            db.session.commit()
            flash('Recenzja została dodana.', 'success')
    except IntegrityError as e:
        db.session.rollback()
        flash('Błąd: Nie można dodać recenzji.', 'error')

    return redirect(url_for('book_details', book_id=book_id))


@app.route('/get_reviews/<int:book_id>', methods=['GET'])
def get_reviews(book_id):
    reviews = BookReviews.query.filter_by(book_id=book_id).all()
    data = [{"user": review.user.username, "review": review.review} for review in reviews]
    return jsonify(data)


@app.route('/add_rating/<int:book_id>', methods=['POST'])
def add_rating(book_id):
    username = session['username']
    user = Users.query.filter_by(username=username).first()

    rating = request.form.get('rating')

    try:
        existing_rating = BookRatings.query.filter_by(book_id=book_id, user_id=user.user_id).first()

        if existing_rating:
            existing_rating.rating = rating
            db.session.commit()
        else:
            new_rating = BookRatings(book_id=book_id, user_id=user.user_id, rating=rating)
            db.session.add(new_rating)
            db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        flash('Błąd: Nie można dodać oceny.', 'error')

    return redirect(url_for('book_details', book_id=book_id))


@app.route('/remove_rating/<int:book_id>', methods=['POST', 'DELETE'])
def remove_rating(book_id):
    try:
        username = session['username']
        user = Users.query.filter_by(username=username).first()

        existing_rating = BookRatings.query.filter_by(book_id=book_id, user_id=user.user_id).first()

        if existing_rating:
            db.session.delete(existing_rating)
            db.session.commit()
            return jsonify({'message': 'Ocena została usunięta z bazy danych.'}), 200
        else:
            return jsonify({'message': 'Brak oceny do usunięcia.'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
