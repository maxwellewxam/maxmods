# Made with love by Max

VER = '2.0.0'

# this file will be the main backbone of our application
# here we will do all out maintenance stuff
# all other files get invoked from here
import machineid
from sqlalchemy import Column, String, LargeBinary
from cryptography.fernet import Fernet
# first we need a database connection
# next we need to grab an authenticator
from .auth import Authenticator
from .database import Database
from .constants import *

class MultiUser:
    def __init__(self, config: Configure = Configure()):
        self.config = config
    
    def __enter__(self):
        self.db = Database(self.config) # make the database connection
        self.config.authenticator_config['db'] = self.db
        self.authenticator = Authenticator(self.config) # then we create the authenticator object with the database connection
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.db.close()
    
    # just make the new_user function available to the user
    def new_user(self, username: str, password: str):
        return self.authenticator.new_user(username, password)
    
    # next we need to let user login
    def login(self, user: User, id:str, username: str, password: str):
        from_auth = self.authenticator.login(username, password, id) # use the authenticator to login
        if from_auth in (BAD_PASS, BAD_USER): # check if the login failed
            return from_auth # if it did, then return the failed result
        user.BAD_USER = False
        user.UUID, user.TOKEN = from_auth
        table = [ # this will hold our users data
            Column('key', String, primary_key=True, nullable=False),
            Column('value', LargeBinary, nullable=False)]
        user.TABLE = self.db.table(user.UUID, table) # create the table for the user 
        return SUCCESS # return the user
    
    # just make the update_username function available to the user properly
    def update_username(self, user: User, password: str, new_username: str):
        if user.BAD_USER:
            return BAD_USER
        return self.authenticator.update_username(user.UUID, password, new_username)
    
    # just make the update_password function available to the user properly
    def update_password(self, user: User, password: str, new_password: str):
        if user.BAD_USER:
            return BAD_USER
        return self.authenticator.update_password(user.UUID, password, new_password)
    
    # make the remove_user function available to the user and some other processing 
    def remove_user(self, user: User, password: str):
        if user.BAD_USER:
            return BAD_USER
        result = self.authenticator.remove_user(user.UUID, password)
        if result != SUCCESS:
            return result
        user.TABLE.drop(self.db.engine)
        return SUCCESS
        
    def find(self, user: User, id: str, key: str):
        if user.BAD_USER:
            return BAD_USER
        from_db = self.db.find(user.TABLE, 'key', key)
        if not from_db:
            return NOT_FOUND
        auth_key = self.authenticator.get_key(user.UUID, user.TOKEN, id)
        if auth_key in (BAD_USER, BAD_HWID, BAD_TOKEN):
            return auth_key
        return Fernet(auth_key).decrypt(from_db[1])
    
    def insert(self, user: User, id: str, key: str, value: bytes):
        if user.BAD_USER:
            return BAD_USER
        if self.db.find(user.TABLE, 'key', key):
            return EXISTS
        auth_key = self.authenticator.get_key(user.UUID, user.TOKEN, id)
        if auth_key in (BAD_USER, BAD_HWID, BAD_TOKEN):
            return auth_key
        self.db.insert(user.TABLE, key=key, value=Fernet(auth_key).encrypt(value))
        return SUCCESS
    
    def update(self, user: User, id: str, key: str, value: bytes):
        if user.BAD_USER:
            return BAD_USER
        if not self.db.find(user.TABLE, 'key', key):
            return NOT_FOUND
        auth_key = self.authenticator.get_key(user.UUID, user.TOKEN, id)
        if auth_key in (BAD_USER, BAD_HWID, BAD_TOKEN):
            return auth_key
        self.db.update(user.TABLE, 'key', key, value=Fernet(auth_key).encrypt(value))
        return SUCCESS
    
    def delete(self, user: User, id: str, key: str):
        if user.BAD_USER:
            return BAD_USER
        from_db = self.db.find(user.TABLE, 'key', key)
        if not from_db:
            return NOT_FOUND
        auth_key = self.authenticator.get_key(user.UUID, user.TOKEN, id)
        if auth_key in (BAD_USER, BAD_HWID, BAD_TOKEN):
            return auth_key
        self.db.delete(user.TABLE, 'key', key)
        return SUCCESS

# this class will be use by our different apis to actual handle the requests
class SingleUser(MultiUser):
    # first we need to initialize all our other objects
    def __init__(self, config: Configure = Configure()):
        self.id = machineid.hashed_id() # get a unique id for the machine the user is using
        self.user = User() # predefine the user value to None
        return super().__init__(config)
    
    def login(self, username: str, password: str):
        return super().login(self.user, self.id, username, password)

    # just make the update_username function available to the user properly
    def update_username(self, password: str, new_username: str):
        return super().update_username(self.user, password, new_username)
    
    # just make the update_password function available to the user properly
    def update_password(self, password: str, new_password: str):
        return super().update_password(self.user, password, new_password)
    
    # make the remove_user function available to the user and some other processing 
    def remove_user(self, password: str):
        return super().remove_user(self.user, password)
        
    def find(self, key: str):
        return super().find(self.user, self.id, key)
    
    def insert(self, key: str, value: bytes):
        return super().insert(self.user, self.id, key, value)
    
    def update(self, key: str, value: bytes):
        return super().update(self.user, self.id, key, value)
    
    def delete(self, key: str):
        return super().delete(self.user, self.id, key)
