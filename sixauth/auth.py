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
import os
from cryptography.hazmat.primitives import hashes, keywrap
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
            Column('uuid', Uuid, primary_key=True, nullable=False), # 0 uuid
            Column('username', String, unique=True, nullable=False), # 1 username
            Column('password', LargeBinary, nullable=False), # 2 password
            Column('salt', LargeBinary, nullable=False), # 3 salt
            Column('edek', LargeBinary, nullable=False), # 4 edek
            Column('esalt', LargeBinary, nullable=False)] # 5 esalt
        self.table = self.db.table('users', table)
        self.store: dict[uuid.UUID, list[list]] = {} # create a dict for tokens
    
    def get_conf(self, db:Database = Database(), max_age = 3600):
        self.db = db
        self.max_age = max_age 
    
    # we need users to authenticate!
    def new_user(self, username: str, password: str):
        if self.db.find(self.table, 'username', username): # ok first we check if the user exists
            return BAD_USER # if they do, we return BAD_USER
        salt = bcrypt.gensalt() # create a salt
        esalt = bcrypt.gensalt() # create a esalt
        hash = bcrypt.hashpw(password.encode(), salt) # hash the password
        dek = os.urandom(32) # create a data encryption key for the user
        key_gen = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=esalt) # make the key gen object
        key = key_gen.derive(password.encode()) # next we generate the key the user needs to access their data encryption key
        edek = keywrap.aes_key_wrap(key, dek, default_backend()) # and wrap the dek with the password derived key
        self.db.insert(self.table, uuid=uuid.uuid4(), username=username, password=hash, salt=salt, edek=edek, esalt=esalt) # insert the new user in the database
        return SUCCESS # and we return SUCCESS
        
    # authenticate users that do exist and generate their key
    def login(self, username: str, password: str, hwid: str):
        from_db = self.db.find(self.table, 'username', username) # first we grab the db entry for the user
        if not from_db: # then we check if the user exists
            return BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode(), from_db[3]): # if they do, we check the password
            return BAD_PASS # if it isn't correct, we return BAD_PASS
        key_gen1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=from_db[5]) # make the first key gen object
        key = key_gen1.derive(password.encode()) # next we generate the key the user needs to access their data encryption key
        dek  = keywrap.aes_key_unwrap(key, from_db[4], default_backend())
        token = secrets.token_urlsafe() # then we generate a token
        key_gen2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=hwid.encode()) # make the second key gen object
        encrypted_key = Fernet(base64.urlsafe_b64encode(key_gen2.derive(token.encode()))).encrypt(dek) # then we encrypt the key with the token and hashed hwid
        if not self.store.get(from_db[0]): # check if the user has a session in the store already
            self.store[from_db[0]] = [] # if not, make one
        self.store[from_db[0]].append([hashlib.sha512(token.encode()).digest(), # then append the hashed token
                                       datetime.now(pytz.utc) + timedelta(seconds=self.max_age), # when the token expires
                                       hwid, # the hwid of the session
                                       encrypted_key]) # and the key the user needs for their data
        return from_db[0], token # then lastly we return the token and uuid
    
    # just search store sessions for token
    def find_token(self, from_store, token):
        for session in from_store:# go over all the sessions
            if session[0] == token: # check if the token of the current session matches the search token
                return session # if a match is found, return the user uuid and the session details
        return None # if no session is found with the given token, return none
    
    # validate hardware and token then return the key
    def get_key(self, uuid: uuid.UUID, token: str, hwid: str):
        from_store = self.store.get(uuid) # grab the user from the store
        if not from_store: # check if the token exists
            return BAD_USER # if it doesn't, we return BAD_USER
        session = self.find_token(from_store, hashlib.sha512(token.encode()).digest()) # search for valid session
        if not session: # check if we found a valid session
            return BAD_TOKEN # if not, we return BAD_TOKEN
        if session[1] <= datetime.now(pytz.utc): # check if token is expired
            return BAD_TOKEN # if it is, we return BAD_TOKEN
        if hwid != session[2]: # check if the hwid is correct
            return BAD_HWID # if the hwid doesn't match, we return BAD_HWID
        session[1] = datetime.now(pytz.utc) + timedelta(seconds=self.max_age) # update the expiry time for the token
        key_generator = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=hwid.encode()) # make key gen object
        decryption_key = base64.urlsafe_b64encode(key_generator.derive(token.encode())) # generate the key
        return base64.urlsafe_b64encode(Fernet(decryption_key).decrypt(session[3])) # if everything is good, we decrypt the user key and return it
    
    # give users the ability to invalidate their token
    def logout(self, uuid: uuid.UUID, token:str, hwid: str):
        from_store = self.store.get(uuid) # grab the user from the store
        if not from_store: # check if the token exists
            return BAD_USER # if it doesn't, we return BAD_USER
        session = self.find_token(from_store, hashlib.sha512(token.encode()).digest()) # search for valid session
        if not session: # check if we found a valid session
            return BAD_TOKEN # if not, we return BAD_TOKEN
        if session[1] <= datetime.now(pytz.utc): # check if token is expired
            return BAD_TOKEN # if it is, we return BAD_TOKEN
        if hwid != session[2]: # check if the hwid is correct
            return BAD_HWID # if the hwid doesn't match, we return BAD_HWID
        from_store.remove(session)  # remove the found session from the user's list of sessions
        if not from_store: # check if the user has no more sessions
            del self.store[uuid] # remove them from the store if they dont
        return SUCCESS # and return SUCCESS
    
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
        from_store = self.store.get(uuid) # grab the user from the store
        if not from_store: # check if the token exists
            return BAD_USER # if it doesn't, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(old_password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return BAD_PASS # if the password is incorrect, we return BAD_PASS
        key_func = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=from_db[5]) # key func to derive keys from
        new_key = key_func.derive(new_password.encode()) # next we generate the old key for the user
        key_func = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=100000, backend=default_backend(), salt=from_db[5]) # key func to derive keys from
        old_key = key_func.derive(old_password.encode()) # and we generate the new key for the user
        dek  = keywrap.aes_key_unwrap(old_key, from_db[4], default_backend())
        edek  = keywrap.aes_key_wrap(new_key, dek, default_backend())
        del self.store[uuid] # then we remove the store entries for the user
        self.db.update(self.table, 'uuid', from_db[0], password=bcrypt.hashpw(new_password.encode('utf-8'), from_db[3]), edek=edek) # update the password in the database
        return SUCCESS # finally we return the keys
    
    # lastly, we can remove users from the database
    def remove_user(self, uuid: uuid.UUID, password:str):
        from_db = self.db.find(self.table, 'uuid', uuid) # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return BAD_PASS # if the password is incorrect, we return BAD_PASS
        self.db.delete(self.table, 'uuid', uuid) # remove the user from the database
        self.store.pop(uuid, None) # then we try to remove the store entries for the user
        return SUCCESS # and we return SUCCESS
    
    # allow a multi user setup to check store for expired tokens to save space
    def flush_store(self):
        for uuid, stored in list(self.store.items()):  # iterate over a copy of the store items
            expired_sessions = [session for session in stored if session[1] <= datetime.now(pytz.utc)] # collect all expired sessions for the current user
            for session in expired_sessions: # go over all expired sessions
                stored.remove(session) # remove the expired session
            if not stored: # check if the user has no more sessions after removal
                del self.store[uuid]  # delete the user's entry from the store
    