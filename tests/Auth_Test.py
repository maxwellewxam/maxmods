import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
sys.path.reverse()
import sixauth
users = dict[sixauth.SingleUser]()
with sixauth.SingleUser(sixauth.Configure()
                          .database(path = f'{os.getcwd()}/db.db')
                          .authenticator(max_age = 3600)) as user:
    print(user.new_user('max', 'max'))
    print(user.login('max', 'max'))
    print(user.insert('bruh', 'lmao'.encode('utf-8')))
    print(user.find('bruh').decode('utf-8'))
    print(user.update_password('max', 'max2'))
with sixauth.SingleUser(sixauth.Configure()
                          .database(path = f'{os.getcwd()}/db.db')
                          .authenticator(max_age = 3600)) as user2:
    print(user2.login('max', 'max2'))
    print(user2.find('bruh').decode('utf-8'))
    print(user2.remove_user('max2'))
sys.exit(0)

for i in range(5):
    users[i] = sixauth.SingleUser(f'{os.getcwd()}/db.db')
    current_user = users[i]
    print(current_user.new_user(f'max{i}', 'max'))
    print(current_user.login(f'max{i}', 'max'))
for i in range(5):
    current_user = users[i]
    print(current_user.user)
    print(current_user.insert('bruh', 'lmao'.encode('utf-8')))
    print(current_user.update('bruh', 'lol2'.encode('utf-8')))
    print(current_user.insert('new', 'lol'.encode('utf-8')))
    print(current_user.find('new').decode('utf-8'))
    print(current_user.find('bruh').decode('utf-8'))
    print(current_user.remove_user('max'))
print(user.login('max', 'max'))
print(user.insert('bruh', 'lmao'.encode('utf-8')))
print(user.update('bruh', 'lol2'.encode('utf-8')))
print(user.insert('new', 'lol'.encode('utf-8')))
print(user.find('new').decode('utf-8'))
print(user.find('bruh').decode('utf-8'))
print(user.insert('skibidy', 'stfu'.encode('utf-8')))
print(user.find('skibidy').decode('utf-8'))
print(user.delete('skibidy'))
print(user.find('skibidy'))
print(user.remove_user('max'))
user.db.close()
sys.exit(0)


logger.setup_logger(log_sensitive = True, log_more = True)
import unittest
# '127.0.0.1:5678'
with ash('127.0.0.1:5678') as user1:

    class testAuth(unittest.TestCase):
        def test_111_login_client_side_wrong_username(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(AuthError) as cm:
                user1.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username does not exist')

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
            
    if __name__ == '__main__':
        unittest.main()
