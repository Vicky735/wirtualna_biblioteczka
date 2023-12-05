from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

db = SQLAlchemy()

class Users(UserMixin, db.Model):
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(32), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    passwd = Column(String(128), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.current_timestamp())
    favourite_genres = relationship('Genres', secondary='user_genres', back_populates='users')

class UserGenres(db.Model):
    user_genre_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    genre_id = Column(Integer, ForeignKey('genres.genre_id'))

class Genres(db.Model):
    genre_id = Column(Integer, primary_key=True, autoincrement=True)
    genre_name = Column(String(256), nullable=False)
    books = relationship('Books', secondary='book_genres', back_populates='genres')
    users = relationship('Users', secondary='user_genres', back_populates='favourite_genres')

class Books(db.Model):
    book_id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(128), nullable=False)
    author = Column(String(128), nullable=False)
    average_rating = Column(Float(precision=2))
    cover_img_url = Column(String(255))
    genres = relationship('Genres', secondary='book_genres', back_populates='books')
    bookshelves = relationship('Bookshelves', secondary='books_on_shelf', back_populates='books')

class BookReviews(db.Model):
    id = Column(Integer, primary_key=True, autoincrement=True)
    book_id = Column(Integer, ForeignKey('books.book_id'))
    user_id = Column(Integer, ForeignKey('users.user_id'))
    rating = Column(Integer)
    review = Column(Text)

class BookGenres(db.Model):
    book_id = Column(Integer, ForeignKey('books.book_id'), primary_key=True)
    genre_id = Column(Integer, ForeignKey('genres.genre_id'), primary_key=True)

class Followers(db.Model):
    relationship_id = Column(Integer, primary_key=True, autoincrement=True)
    follower_id = Column(Integer, ForeignKey('users.user_id'))
    followed_id = Column(Integer, ForeignKey('users.user_id'))

class Bookshelves(db.Model):
    shelf_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    shelf_name = Column(String(64))
    books = db.relationship('Books', secondary='books_on_shelf', back_populates='bookshelves')

class BooksOnShelf(db.Model):
    entry_id = Column(Integer, primary_key=True, autoincrement=True)
    shelf_id = Column(Integer, ForeignKey('bookshelves.shelf_id'))
    book_id = Column(Integer, ForeignKey('books.book_id'))
