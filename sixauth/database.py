# Made with love by Max

# this file will handle all database related stuff
# all we need is a database connection 

from sqlalchemy import create_engine, Column, Table, MetaData
from sqlalchemy.pool import StaticPool 
from .constants import *
import os
        
class Database:
    # first we connect to the database
    def __init__(self, config: Configure = Configure()):
        self.get_conf(**config.database_config)
        db_path = f'sqlite:///{self.path}' # define the path to the database
        self.engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool) # create a database engine
        self.metadata = MetaData() # metadata for the database
        self.connection = self.engine.connect() # connect to the database
    
    def get_conf(self, path = os.path.join(os.getcwd(),'db.db')):
        self.path = path
    
    # we need this to save everything to the database when we are done
    def close(self):
        self.connection.commit()
        self.connection.close()
    
    # this allows people to create multiple tables in one db
    def table(self, name, columns:list[Column]):
        table = Table(name, self.metadata) # create the table with our metadata
        for column in columns: # then for every column
                table.append_column(column, replace_existing=True) # append the column to the table
        self.metadata.create_all(self.engine) # then push the table into the db
        self.connection.commit() # and commit
        return table
    
    # we need to grab things from the database
    def find(self, table:Table, column, key):
        clause = getattr(table.c, column) == key
        ex = table.select().where(clause)
        return self.connection.execute(ex).fetchone()
    
    # we need to insert things into the database
    def insert(self, table:Table, **values):
        ex = table.insert().values(**values)
        result = self.connection.execute(ex)
        self.connection.commit()
        return result
    
    # we need to update things in the database
    def update(self, table:Table, column, key, **values):
        clause = getattr(table.c, column) == key
        ex = table.update().where(clause).values(**values)
        result = self.connection.execute(ex)
        self.connection.commit()
        return result
    
    # we need to delete things from the database
    def delete(self, table:Table, column, key):
        clause = getattr(table.c, column) == key
        ex = table.delete().where(clause)
        result = self.connection.execute(ex)
        self.connection.commit()
        return result
    
    def multi_find(self, table: Table):
        ex = table.select()
        results = self.connection.execute(ex)
        for row in results:
            yield row
        