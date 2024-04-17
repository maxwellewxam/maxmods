import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
sys.path.reverse()
import sixauth
import unittest
import hashlib
import machineid
import pytz
from datetime import datetime, timedelta
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.exc import SQLAlchemyError
hwid = machineid.hashed_id()
configuration = sixauth.Configure().database(path = os.path.join(os.getcwd(),'test.db'))
database = sixauth.auth.Database(configuration)
configuration.authenticator(db = database, exceptions = False)
def clear_db(engine):
    Base = automap_base()
    Base.prepare(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        print(f"An error occurred: {e}")
    finally:
        session.close()

class testAuth(unittest.TestCase):
    def test_111_new_user(self):
        test = sixauth.Authenticator(configuration)
        clear_db(test.db.engine)
        self.assertEqual(test.new_user('max','password'), sixauth.SUCCESS)
        self.assertEqual(test.new_user('max','password'), sixauth.BAD_USER)
        
    def test_112_login(self):
        test = sixauth.Authenticator(configuration)
        clear_db(test.db.engine)
        self.assertEqual(test.login('max','password',hwid), sixauth.BAD_USER)
        test.new_user('max','password')
        self.assertEqual(test.login('max','badpassword',hwid), sixauth.BAD_PASS)
        self.assertNotIn(test.login('max','password',hwid), sixauth.ALL)
        
    def test_113_get_key(self):
        test = sixauth.Authenticator(configuration)
        clear_db(test.db.engine)
        self.assertEqual(test.get_key('bad_uuid','bad_token',hwid), sixauth.BAD_USER)
        test.new_user('max','password')
        uuid, token = test.login('max','password',hwid)
        self.assertEqual(test.get_key(uuid,'bad_token',hwid), sixauth.BAD_TOKEN)
        from_store = test.store.get(uuid)
        store = test.find_token(from_store, hashlib.sha512(token.encode()).digest())
        store[1] = datetime.now(pytz.utc)
        self.assertEqual(test.get_key(uuid,token,hwid), sixauth.BAD_TOKEN)
        store[1] = datetime.now(pytz.utc) + timedelta(seconds=3600)
        self.assertEqual(test.get_key(uuid,token,'hwid'), sixauth.BAD_HWID)
        self.assertNotIn(test.get_key(uuid,token,hwid), sixauth.ALL)
        
    
"""
    def test_112_login_client_side_no_username(self):
        user1.set_vals('', 'test')
        with self.assertRaises(AuthError) as cm:
            user1.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Invalid username')
    
    def test_121_login_client_side_bad_pass(self):
        user1.set_vals('test', 'max')
        with self.assertRaises(AuthError) as cm:
            user1.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Incorrect password')
    
    def test_113_signup_client_side_success(self):
        user1.set_vals('test', 'test')
        self.assertTrue(user1.signup())
    
    def test_122_login_client_side_success(self):
        user1.set_vals('test', 'test')
        self.assertTrue(user1.login())
    
    def test_123_signup_client_side_bad_username(self):
        user1.set_vals('test', 'test')
        with self.assertRaises(AuthError) as cm:
            user1.signup()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username "test" already exists')
    
    def test_131_save_client_side_success(self):
        user1.set_vals('test', 'test')
        self.assertTrue(user1.save('Test/Test', 'UR MOM'))
    
    def test_132_load_client_side_success(self):
        user1.set_vals('test', 'test')
        self.assertEqual(user1.load('Test/Test'), 'UR MOM')
        
    def test_133_load_client_side_doesnt_exist(self):
        user1.set_vals('test', 'test')
        with self.assertRaises(AuthError) as cm:
            user1.load('John/Green/Rubber/Co')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Location does not exist')
        
    def test_134_save_client_side_whole_dict(self):
        user1.set_vals('test', 'test')
        with self.assertRaises(AuthError) as cm:
            user1.save('', {'URMOM':'test'})
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'No path specified')
        
    def test_135_load_client_side_all_data(self):
        user1.set_vals('test', 'test')
        self.assertEqual(user1.load(''), {'Test': {'data': None, 'folder': {'Test': {'data': 'UR MOM', 'folder': {}}}}})

    def test_199_remove_client_side_success(self):
        user1.set_vals('test', 'test')
        self.assertTrue(user1.remove())
"""
if __name__ == '__main__':
    unittest.main()
