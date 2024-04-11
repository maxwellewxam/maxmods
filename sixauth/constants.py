BAD_PASS = 'BAD_PASS'
BAD_USER = 'BAD_USER'
BAD_TOKEN = 'BAD_TOKEN'
BAD_HWID = 'BAD_HWID'
SUCCESS = 'SUCCESS'
NOT_FOUND = 'NOT_FOUND'
EXISTS = 'EXISTS'

ALL = (BAD_HWID, BAD_USER, BAD_TOKEN, BAD_PASS, NOT_FOUND, EXISTS, SUCCESS)

class User:
    BAD_USER = True
    TOKEN = None
    UUID = None
    TABLE = None
    
class Configure:
    def __init__(self):
        self.database_config = {}
        self.authenticator_config = {}
    def database(self, **kwargs):
        self.database_config = kwargs
        return self
    
    def authenticator(self, **kwargs):
        self.authenticator_config = kwargs
        return self