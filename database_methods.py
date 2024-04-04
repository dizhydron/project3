from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import datetime
import sqlite3
import uuid
import secrets
import argon2
import os

db_filename = "totally_not_my_privateKeys.db" # the name of the database file

# the following functions provide information for the test suite for project 2

def get_bd_filename(): 
    return db_filename # return the database filename

def table_schema_check():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''SELECT * FROM keys''') # execute a query
    result = c.fetchone() # get the result
    connect.close() # close the connection
    return result # return the result

#the following functions are for the server. Some are for porject2, others are for project3

def create_database():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''') # create the keys table
    connect.commit() # commit the changes
    connect.close() # close the connection

def create_users_table():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''') # create the users table
    connect.commit() # commit the changes
    connect.close() # close the connection

def create_auth_table():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''') # create the auth_logs table
    connect.commit() # commit the changes
    connect.close() # close the connection

def save_user_to_db(username, password_hash, email, date_registered, last_login):
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        INSERT INTO users (username, password_hash, email, date_registered, last_login) VALUES (?, ?, ?, ?, ?)
    ''', (username, password_hash, email, date_registered, last_login)) # insert the user into the database
    connect.commit() # commit the changes
    connect.close() # close the connection

def get_user_from_db():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        SELECT * FROM users
    ''') # select all users from the database
    result = c.fetchall() # get the result
    connect.close() # close the connection
    return result # return the result

def save_auth_to_db(request_ip, request_timestamp, user_id):
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)
    ''', (request_ip, request_timestamp, user_id)) # insert the auth log into the database
    connect.commit() # commit the changes
    connect.close() # close the connection

def get_auth_from_db():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        SELECT * FROM auth_logs
    ''') # select all auth logs from the database
    result = c.fetchall() # get the result
    connect.close() # close the connection
    return result # return the result

#The following functions are for project3 and are currently incomplete

def create_enviroment_var():
    name = "NOT_MY_KEY"
    key = get_random_bytes(16)
    key_string = key.hex()  # Convert bytes key to hexadecimal string
    os.environ[name] = key_string

def get_enviroment_var():
    name = "NOT_MY_KEY"
    key_string = os.environ.get(name)
    if key_string:
        key = bytes.fromhex(key_string)  # Convert hexadecimal string to bytes
        return key
    else:
        return None

def encrypt_private_key_AES(key, text):
    if isinstance(text, str):
        text = text.encode('utf-8')
    padded_text = pad(text, AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

def decrypt_private_key_AES(key, text):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = cipher.decrypt(text)
    unpadded_text = unpad(decrypted_text, AES.block_size)
    return unpadded_text

def generate_secure_password_UUIDv4():
    uuid_str = str(uuid.uuid4()) # generate a UUIDv4
    return uuid_str # return the UUIDv4

def hash_password_argon2(password):
    salt = secrets.token_urlsafe(16) # generate a random salt
    time_cost = 2 # set the time cost
    memory_cost = 102400 # set the memory cost
    parallelism = 2 # set the parallelism
    hash_len = 16 # set the hash length
    hasher = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=hash_len) # create a password hasher
    hash_str = hasher.hash(password + salt) # hash the password
    return hash_str, salt # return the hash and salt

def create_private_test_key():
    private_key = RSA.generate(4096, e=65539) # generate a private key
    pem = private_key.export_key(format='PEM') # export the private key to a PEM
    date = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) # set the date to the epoch
    time_since = datetime.datetime.now(datetime.timezone.utc) - date # get the time since the epoch
    seconds = int(time_since.total_seconds()) + 3600 # convert the time since the epoch to seconds
    key = (pem, seconds) # create the key
    return key # return the key

def create_expired_test_key():
    expired_key = RSA.generate(4096, e=65539) # generate an expired private key
    expired_pem = expired_key.export_key(format='PEM') # export the expired private key to a PEM
    exp_date = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) # set the expiration date to the epoch
    exp_time_since = datetime.datetime.now(datetime.timezone.utc) - exp_date # get the time since the epoch
    exp_seconds = int(exp_time_since.total_seconds()) - 3600 # convert the time since the epoch to seconds
    exp_key = (expired_pem, exp_seconds) # create the expired key
    return exp_key # return the expired key

def save_private_key_to_db(key_bytes, expiration):
    encryption_key = get_enviroment_var()
    AES_key = encrypt_private_key_AES(encryption_key, key_bytes)
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (AES_key, expiration)) # insert the key into the database
    connect.commit() # commit the changes
    connect.close() # close the connection

def get_private_key_from_db(expired=False):
    encryption_key = get_enviroment_var()   
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    if expired: # if the key is expired
        c.execute('''
            SELECT key, exp, kid FROM keys WHERE exp <= strftime('%s', 'now')
        ''') # select the expired key from the database
    else: # if the key is unexpired
        c.execute('''
            SELECT key, exp, kid FROM keys WHERE exp >= strftime('%s', 'now')
        ''') # select the unexpired key from the database
    result = c.fetchone() # get the result
    connect.close() # close the connection
    new_result = result[0]
    decrypted_key = decrypt_private_key_AES(encryption_key, new_result)
    result2 = (decrypted_key, result[1], result[2])
    return result2 # return the result

def get_unexpired_keys():
    connect = sqlite3.connect(db_filename) # connect to the database
    c = connect.cursor() # create a cursor
    c.execute('''
        SELECT key, exp, kid FROM keys WHERE exp >= strftime('%s', 'now')
    ''') # select the unexpired keys from the database
    result = c.fetchall() # get the result
    connect.close() # close the connection
    return result # return the result