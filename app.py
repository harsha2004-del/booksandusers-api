from flask import Flask, request, jsonify
import sqlite3
import jwt
import datetime
from functools import wraps
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'your_secret_key'

def change(query, params=()):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        result = cursor.fetchall()
        conn.commit()
    except sqlite3.IntegrityError as e:
        result = str(e)
    finally:
        conn.close()
    return result

def create_tables():
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        published_year INTEGER,
        genre TEXT,
        available_copies INTEGER
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        membership_type TEXT,
        registered_date TEXT
    )
    """)
    conn.commit()
    conn.close()

create_tables()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['email']
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the Library API"})

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    membership_type = data.get('membership_type', 'Regular')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    registered_date = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    query = """
    INSERT INTO users (name, email, password, membership_type, registered_date)
    VALUES (?, ?, ?, ?, ?)
    """
    change(query, (name, email, hashed_password, membership_type, registered_date))
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = change("SELECT * FROM users WHERE email = ?", (email,))
    if user and bcrypt.check_password_hash(user[0][3], password):
        token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                           app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/books', methods=['GET'])
def get_books():
    query = "SELECT * FROM books"
    books = change(query)
    if not books:
        return jsonify({"message": "No books found"}), 404
    books_list = [{"id": b[0], "title": b[1], "author": b[2], "published_year": b[3], "genre": b[4], "available_copies": b[5]} for b in books]
    return jsonify(books_list)

@app.route('/api/books/<int:id>', methods=['GET'])
def get_book_by_id(id):
    query = "SELECT * FROM books WHERE id = ?"
    book = change(query, (id,))
    if not book:
        return jsonify({"message": "Book not found"}), 404
    book_data = {"id": book[0][0], "title": book[0][1], "author": book[0][2], "published_year": book[0][3], "genre": book[0][4], "available_copies": book[0][5]}
    return jsonify(book_data), 200

@app.route('/api/books', methods=['POST'])
@token_required
def add_book(current_user):
    data = request.get_json()
    title = data.get("title")
    author = data.get("author")
    published_year = data.get("published_year")
    genre = data.get("genre")
    available_copies = data.get("available_copies")
    if not title or not author or not isinstance(available_copies, int):
        return jsonify({"message": "Invalid data provided"}), 400
    existing_book = change("SELECT * FROM books WHERE title = ? AND author = ?", (title, author))
    if existing_book:
        return jsonify({"message": "Book with this title and author already exists!"}), 400
    query = """
    INSERT INTO books (title, author, published_year, genre, available_copies)
    VALUES (?, ?, ?, ?, ?)
    """
    change(query, (title, author, published_year, genre, available_copies))
    return jsonify({"message": "Book added successfully", "book": data}), 201

@app.route('/api/books/<int:id>', methods=['PUT'])
@token_required
def update_book(current_user, id):
    data = request.get_json()
    title = data.get("title")
    author = data.get("author")
    published_year = data.get("published_year")
    genre = data.get("genre")
    available_copies = data.get("available_copies")

    if not title or not author or not isinstance(available_copies, int):
        return jsonify({"message": "Invalid data provided"}), 400
    
    book = change("SELECT * FROM books WHERE id = ?", (id,))
    if not book:
        return jsonify({"message": "Book not found"}), 404

    query = """
    UPDATE books
    SET title = ?, author = ?, published_year = ?, genre = ?, available_copies = ?
    WHERE id = ?
    """
    change(query, (title, author, published_year, genre, available_copies, id))
    return jsonify({"message": "Book updated successfully"})


@app.route('/api/books/<int:id>', methods=['DELETE'])
@token_required
def delete_book(current_user, id):
    delete_query = "DELETE FROM books WHERE id = ?"
    change(delete_query, (id,))
    return jsonify({"message": "Book deleted successfully"})

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    query = "SELECT * FROM users"
    users = change(query)
    if not users:
        return jsonify({"message": "No users found"}), 404
    users_list = [{"id": user[0], "name": user[1], "email": user[2], "membership_type": user[4], "registered_date": user[5]} for user in users]
    return jsonify(users_list), 200

@app.route('/api/users/<int:id>', methods=['GET'])
@token_required
def get_user(current_user, id):
    query = "SELECT * FROM users WHERE id = ?"
    user = change(query, (id,))
    if not user:
        return jsonify({"message": "User not found"}), 404
    user_data = {"id": user[0][0], "name": user[0][1], "email": user[0][2], "membership_type": user[0][4], "registered_date": user[0][5]}
    return jsonify(user_data)

@app.route('/api/users/<int:id>', methods=['PUT'])
@token_required
def update_user(current_user, id):
    data = request.get_json()
    name = data.get("name")
    membership_type = data.get("membership_type")
    
    if not name or not membership_type:
        return jsonify({"message": "Invalid data provided"}), 400
    
    user = change("SELECT * FROM users WHERE id = ?", (id,))
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    query = """
    UPDATE users
    SET name = ?, membership_type = ?
    WHERE id = ?
    """
    change(query, (name, membership_type, id))
    return jsonify({"message": "User updated successfully"})


@app.route('/api/users/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    query = "DELETE FROM users WHERE id = ?"
    change(query, (id,))
    return jsonify({"message": "User deleted successfully"})

if __name__ == '__main__':
    app.run(debug=True)
