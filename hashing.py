import bcrypt 
from pymongo import MongoClient

def connect_to_mongodb():
    client = MongoClient('mongodb://localhost:27017/userDB')
    db = client['userDB']
    return db

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt

def store_user(username, email, password):
    db = connect_to_mongodb()
    users_collection = db['users']
    
    hashed_password, salt = hash_password(password)
    
    user = {
        'username': username,
        'email': email,
        'passwordHash': hashed_password,
        'salt': salt
    }
    
    result = users_collection.insert_one(user)
    print(f'New user created with the following id: {result.inserted_id}')

def verify_password(username, password):
    db = connect_to_mongodb()
    users_collection = db['users']
    
    user = users_collection.find_one({'username': username})
    if not user:
        print('User not found')
        return False
    
    stored_hashed_password = user['passwordHash']
    
    is_match = bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password)
    if is_match:
        print('Login successful')
        return True
    else:
        print('Invalid password')
        return False