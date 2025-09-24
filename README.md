# Secure Phonebook API

A secure phonebook REST API built with FastAPI, featuring authentication, role-based access control, input validation and audit logging.

## Features

- Add, list, and delete phonebook entries
- JWT authentication with read and read-write roles
- Input validation for names and phone numbers
- Audit logging for all actions
- Docker support

## Requirements

- Python 3.10+
- See [requirements.txt](requirements.txt)

## Setup

1. **Install dependencies:**
sh pip install -r requirements.txt
2. **Run the API:**
sh uvicorn app:app --reload
3. **API Docs:**
   - Visit [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Docker

Build and run with Docker:
sh docker build -t secure-phonebook . docker run -p 8000:8000 secure-phonebook
## Testing

- Use the included [Phonebook -prajeeth.postman_collection.json](Phonebook%20-prajeeth.postman_collection.json) for API tests in Postman.

## Files

- `app.py`: Main FastAPI application
- `requirements.txt`: Python dependencies
- `Dockerfile`: Docker build instructions
- `phonebook.db`: SQLite database
- `phonebook_audit.log`: Audit log file
