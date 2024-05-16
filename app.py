from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_EXPIRATION_DELTA'] = timedelta(days=1)
app.config['RESULTS_PER_PAGE'] = 2
app.config['JWT_SECRET_KEY'] = 'nihad-jwt-secret' 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    publication_date = db.Column(db.Date)
    genre = db.Column(db.String(50))
    isbn = db.Column(db.String(20))

    def __repr__(self):
        return f'<Book {self.title}>'
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200    

@app.route('/books', methods=['GET'])
def get_books():
    books = Book.query.all()
    result = [{'id': book.id, 'title': book.title, 'author': book.author, 'publication_date': str(book.publication_date), 'genre': book.genre, 'isbn': book.isbn} for book in books]
    return jsonify(result)

@app.route('/books', methods=['POST'])
@jwt_required()
def add_book():
    data = request.json
    if 'publication_date' in data and data['publication_date']:
        publication_date = datetime.strptime(data['publication_date'], '%Y-%m-%d').date()
    else:
        publication_date = None

    new_book = Book(
        title=data['title'],
        author=data['author'],
        publication_date=publication_date,
        genre=data.get('genre'),
        isbn=data.get('isbn')
    )
    db.session.add(new_book)
    db.session.commit()
    return jsonify({'message': 'Book added successfully'}), 201

@app.route('/books/<int:id>', methods=['PUT'])
@jwt_required()
def update_book(id):
    data = request.json
    book = Book.query.get(id)
    if not book:
        return jsonify({'message': 'Book not found'}), 404
    book.title = data.get('title', book.title)
    book.author = data.get('author', book.author)
    book.publication_date = data.get('publication_date', book.publication_date)
    book.genre = data.get('genre', book.genre)
    book.isbn = data.get('isbn', book.isbn)
    db.session.commit()
    return jsonify({'message': 'Book updated successfully'})

@app.route('/books/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_book(id):
    book = Book.query.get(id)
    if not book:
        return jsonify({'message': 'Book not found'}), 404
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': 'Book deleted successfully'})

# Search functionality
@app.route('/books/search', methods=['GET'])
def search_books():
    query = request.args.get('query')
    if query:
        books = Book.query.filter(Book.title.ilike(f'%{query}%') | Book.author.ilike(f'%{query}%') | Book.genre.ilike(f'%{query}%'))
    else:
        books = Book.query.all()
    result = [{'id': book.id, 'title': book.title, 'author': book.author, 'publication_date': str(book.publication_date), 'genre': book.genre, 'isbn': book.isbn} for book in books]
    return jsonify(result)

def get_books_for_page(page, per_page):
    books = Book.query.paginate(page=page, per_page=per_page, error_out=False).items
    return books

# Define a function to serialize books
def serialize_books(books):
    return [{'id': book.id, 'title': book.title, 'author': book.author, 
             'publication_date': str(book.publication_date), 'genre': book.genre, 'isbn': book.isbn} 
            for book in books]

# Pagination route
@app.route('/books/page/<int:page>', methods=['GET'])
def paginate_books(page):
    per_page = app.config['RESULTS_PER_PAGE']
    books = get_books_for_page(page, per_page)
    result = serialize_books(books)
    return jsonify(result)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
