import sqlite3

class Db:
    """Database class
    """

    def __init__(self):
        self.db_name = "passwords.db"
        self.db = sqlite3.connect(self.db_name)
        self.cursor = self.db.cursor()
        # check if all tables exist
        if not self.check_if_table_exists("passwords"):
            self.create_table("passwords", "username text, passwords text")
        if not self.check_if_table_exists("master_passwords"):
            self.create_table("master_passwords", "username text, password text")

    def escape(self, string):
        """Escape string to prevent SQL injection

        Args:
            string (str): String to escape
        
        Returns:
            str: Escaped string
        """
        return string.replace("'", "''")

    def read(self, table, column, value):
        """Reads data from database

        Args:
            table (str): Table to read from
            column (str): Column to read from
            value (str): Value to read from

        Returns:
            list: Data from database
        """
        table = self.escape(table)
        column = self.escape(column)
        value = self.escape(value)
        self.cursor.execute("SELECT * FROM {} WHERE {} = '{}'".format(table, column, value))
        return self.cursor.fetchall()

    def write(self, table, column, value, data):
        """Writes data to database

        Args:
            table (str): Table to write to
            column (str): Column to write to
            value (str): Value to write to
            data (str): Data to write
        """
        table = self.escape(table)
        column = self.escape(column)
        value = self.escape(value)
        data = self.escape(data)
        self.cursor.execute("INSERT INTO {} ({}) VALUES ('{}', '{}')".format(table, column, value, data))
        self.db.commit()

    def remove(self, table, column, value):
        """Removes data from database

        Args:
            table (str): Table to remove from
            column (str): Column to remove from
            value (str): Value to remove from
        """
        table = self.escape(table)
        column = self.escape(column)
        value = self.escape(value)
        self.cursor.execute("DELETE FROM {} WHERE {} = '{}'".format(table, column, value))
        self.db.commit()

    def get_passwords(self, username):
        """Gets passwords from database

        Args:
            username (str): Username to get passwords for

        Returns:
            str: Passwords
        """
        return self.read("passwords", "username", username)[0][1]
    
    def get_master_password(self, username):
        """Gets master password hash from database

        Args:
            username (str): Username to get master password for

        Returns:
            str: Master password hash
        """
        return self.read("master_passwords", "username", username)[0][1]

    def check_if_table_exists(self, table):
        """Checks if table exists
        
        Args:
            table (str): Table to check

        Returns:
            Bool: True if table exists, False if not
        """
        table = self.escape(table)
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='{}'".format(table))
        return len(self.cursor.fetchall()) > 0

    def check_if_user_exists(self, username):
        """Checks if user exists

        Args:
            username (str): Username to check

        Returns:
            Bool: True if user exists, False if not
        """
        username = self.escape(username)
        self.cursor.execute("SELECT * FROM master_passwords WHERE username = '{}'".format(username))
        return len(self.cursor.fetchall()) > 0

    def create_table(self, table, columns):
        """Creates table in database

        Args:
            table (str): Table to create
            columns (str): Columns to create
        """
        table = self.escape(table)
        columns = self.escape(columns)
        self.cursor.execute("CREATE TABLE {} ({})".format(table, columns))
        self.db.commit()
    
