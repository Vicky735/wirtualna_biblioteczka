import psycopg2
import json

db_params = {
    'host': 'localhost',
    'database': 'virtual_library',
    'user': 'postgres',
    'password': 'passwd',
    'port': '5432'
}

with open('genres.json', 'r', encoding='utf8') as genres_file:
    genres_to_insert = json.load(genres_file)

with open('books.json', 'r', encoding='utf8') as books_file:
    data_to_insert = json.load(books_file)

try:
    connection = psycopg2.connect(**db_params)
    cursor = connection.cursor()

    insert_genre_query = "INSERT INTO genres (genre_name) VALUES (%s)"
    insert_book_query = "INSERT INTO books (title, author, cover_img_url) VALUES (%s, %s, %s) RETURNING book_id"
    insert_book_genres_query = "INSERT INTO book_genres (book_id, genre_id) VALUES (%s, %s)"

    # Dodawanie gatunków do tabeli genres
    for genre_name in genres_to_insert:
        cursor.execute(insert_genre_query, (genre_name,))

    for entry in data_to_insert:
        # Wstaw informacje o książce i pobierz book_id
        cursor.execute(insert_book_query, (entry['title'], entry['author'], entry['cover_img_url']))
        book_id = cursor.fetchone()[0]

        # Wstaw informacje o gatunkach dla danej książki
        if 'genres' in entry:
            for genre_name in entry['genres']:
                cursor.execute("SELECT genre_id FROM genres WHERE genre_name = %s", (genre_name,))
                genre_id = cursor.fetchone()[0]
                cursor.execute(insert_book_genres_query, (book_id, genre_id))

    connection.commit()
    cursor.close()
    connection.close()

    print("Data successfully inserted into the 'genres', 'books' and 'book_genres' tables.")

except Exception as e:
    print(f"Error: {e}")
