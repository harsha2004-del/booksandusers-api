A RESTful API built with Flask, SQLite, and JWT for managing users and books in a library system. This project supports user authentication, CRUD operations for books, and user management.
Below are the end points:
POST /api/auth/register,
POST /api/auth/login,
GET /api/books,
GET /api/books/<int:id>,
POST /api/books,
PUT /api/books/<int:id>,
GET /api/users,
GET /api/users/<int:id>,
DELETE /api/users/<int:id>,
PUT /api/users/<int:id>,
except for get books all other require jwt token.
place the token in header of postman --- key:x-access-token,value:<token>.
