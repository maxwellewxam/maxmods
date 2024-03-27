# Made with love by Max

# this file will handle all authentication related stuff
# all we need is ways to authenticate,
# create, delete, and update users

import bcrypt
import uuid
import secrets
import base64
import pytz
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from sqlalchemy import Column, String, LargeBinary, Uuid
from datetime import datetime, timedelta
from .database import Database
from .constants import *
        
class Authenticator:
    # first we connect to the database
    def __init__(self, config: Configure = Configure()):
        self.get_conf(**config.authenticator_config)
        table = [ # this will hold our users and their passwords
            Column('uuid', Uuid, primary_key=True, nullable=False),
            Column('username', String, unique=True, nullable=False),
            Column('password', LargeBinary, nullable=False),
            Column('salt', LargeBinary, nullable=False)]
        self.table = self.db.table('users', table)
        self.store = {} # create a dict for tokens
    
    def get_conf(self, db:Database = Database(), max_age = 3600):
        self.db = db
        self.max_age = max_age 
    
    # we need users to authenticate!
    def new_user(self, username: str, password: str):
        if self.db.find(self.table, 'username', username): # ok first we check if the user exists
            return BAD_USER # if they do, we return BAD_USER
        salt = bcrypt.gensalt() # create a salt
        hash = bcrypt.hashpw(password.encode(), salt) # hash the password
        self.db.insert(self.table, uuid=uuid.uuid4(), username=username, password=hash, salt=salt) # insert the new user in the database
        return SUCCESS # and we return SUCCESS
        
    # authenticate users that do exist and generate their key
    def login(self, username: str, password: str, hwid: str):
        from_db = self.db.find(self.table, 'username', username) # first we grab the db entry for the user
        if not from_db: # then we check if the user exists
            return BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode(), from_db[3]): # if they do, we check the password
            return BAD_PASS # if it isn't correct, we return BAD_PASS
        key_gen1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=from_db[0].bytes) # make the first key gen object
        key = base64.urlsafe_b64encode(key_gen1.derive(password.encode())) # next we generate the key the user needs to access their data
        token = secrets.token_urlsafe() # then we generate a token
        key_gen2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=hwid.encode()) # make the second key gen object
        encrypted_key = Fernet(base64.urlsafe_b64encode(key_gen2.derive(token.encode()))).encrypt(key) # then we encrypt the key with the token and hashed HWID
        self.store[from_db[0]] = [hashlib.sha512(token.encode()).digest(), datetime.now(pytz.utc) + timedelta(seconds=self.max_age), hwid, encrypted_key] # add the hashed token, expiry date, hwid, and encrypted key to the store
        return (from_db[0], token) # then lastly we return the token and uuid
    
    # validate hardware and token then return the key
    def get_key(self, uuid: uuid.UUID, token: str, hwid: str):
        from_store = self.store.get(uuid) # grab the token from the store
        if not from_store: # check if the token exists
            return BAD_USER # if it doesn't, we return BAD_USER
        if hashlib.sha512(token.encode()).digest() != from_store[0]: # next we check the token provided against the one in the store
            return BAD_TOKEN # if it isn't correct, we return BAD_TOKEN
        if from_store[1] <= datetime.now(pytz.utc): # check if token is expired
            return BAD_TOKEN # if it is, we return BAD_TOKEN
        if hwid != from_store[2]: # check if the hwid is correct
            return BAD_HWID # if the hwid doesn't match, we return BAD_HWID
        from_store[1] = datetime.now(pytz.utc) + timedelta(seconds=self.max_age) # update the expiry time for the token
        key_generator = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=hwid.encode()) # make key gen object
        decryption_key = base64.urlsafe_b64encode(key_generator.derive(token.encode())) # generate the key
        return Fernet(decryption_key).decrypt(from_store[3]) # if everything is good, we decrypt the user key and return it
    
    # give users the ability to invalidate their token
    def logout(self, uuid: uuid.UUID, token:str, hwid: str):
        from_store = self.store.get(uuid) # grab the token from the store
        if not from_store: # check if the token exists
            return BAD_USER # if it doesn't, we return BAD_USER
        if hashlib.sha512(token.encode()).digest() != from_store[0]: # next we check the token provided against the one in the store
            return BAD_TOKEN # if it isn't correct, we return BAD_TOKEN
        if from_store[1] <= datetime.now(pytz.utc): # check if token is expired
            return BAD_TOKEN # if it is, we return BAD_TOKEN
        if hwid != from_store[2]: # check if the hwid is correct
            return BAD_HWID # if the hwid doesn't match, we return BAD_HWID
        self.store.pop(uuid) # once all is good, we remove their token from the store
        return SUCCESS # and return success
    
    # allow users to change their username
    def update_username(self, uuid: uuid.UUID, password: str, new_username: str):
        from_db = self.db.find(self.table, 'uuid', uuid) # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return BAD_PASS # if the password is incorrect, we return BAD_PASS
        if self.db.find(self.table, 'username', new_username): # check if the new username already exists
            return BAD_USER # if it does, we return BAD_USER
        self.db.update(self.table, 'uuid', uuid, username=new_username) # update the username in the database
        return SUCCESS  # and we return SUCCESS
    
    # allow users to change their password
    def update_password(self, uuid: uuid.UUID, old_password: str, new_password: str):
        from_db = self.db.find(self.table, 'uuid', uuid) # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(old_password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return BAD_PASS # if the password is incorrect, we return BAD_PASS
        self.db.update(self.table, 'uuid', uuid, password=bcrypt.hashpw(new_password.encode('utf-8'), from_db[3])) # update the password in the database
        key_func = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=from_db[0].bytes) # key func to derive keys from
        new_key = base64.urlsafe_b64encode(key_func.derive(new_password.encode())) # next we generate the old key for the user
        old_key = base64.urlsafe_b64encode(key_func.derive(old_password.encode())) # next we generate the new key for the user
        self.store.pop(uuid, None) # then we try to remove the store entry for the user
        return old_key, new_key # finally we return the keys
    
    # lastly, we can remove users from the database
    def remove_user(self, uuid: uuid.UUID, password:str):
        from_db = self.db.find(self.table, 'uuid', uuid) # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return BAD_PASS # if the password is incorrect, we return BAD_PASS
        self.db.delete(self.table, 'uuid', uuid) # remove the user from the database
        return SUCCESS # and we return SUCCESS
    
    # allow a multi user setup to check store for expired tokens to save space
    def flush_store(self):
        for uuid, stored in list(self.store.items()): # go over everything in the store
            if stored[1] <= datetime.now(pytz.utc): # check if token is expired
                self.store.pop(uuid) # if its expired, remove it!
    