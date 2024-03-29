import sqlite3
from threading import Lock

class DataBase:

    def __init__(self):
        # Connect to the database (creates the file if it doesn't exist)
        self.conn = sqlite3.connect('defensive.db')

        self.cursor = self.conn.cursor()

        # Create the 'clients' table if it doesn't exist
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
                               client_id BLOB(16) PRIMARY KEY,
                               client_name TEXT(255),
                               public_key BLOB(160),
                               last_seen TEXT,
                               AES_key BLOB(32)
                           )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                                     client_id BLOB(16),
                                     file_name TEXT(255),
                                     path_name TEXT(255),
                                     verified BOOL,
                                     PRIMARY KEY (client_id, file_name)
                                 )''')

        # Commit the changes and close the connection
        self.lock = Lock()
        self.conn.commit()

    """Adding client to database"""
    def add_client(self,client_id: bytes, client_name: str, public_key: bytes, last_seen: str, AES_key: bytes):
        # Connect to the database
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()

            # Execute the INSERT statement
            self.cursor.execute("INSERT INTO clients (client_id, client_name, public_key, last_seen, AES_key) VALUES (?, ?, ?, ?, ?)",
                           (client_id, client_name, public_key, last_seen, AES_key))

            # Commit the changes and close the connection
            self.conn.commit()
            self.conn.close()
    """Adding file to database"""
    def add_file(self, client_id: bytes, file_name: str, path_name: str, verified: bool):
        # Connect to the database
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()

            # Execute the INSERT or Replace statement
            self.cursor.execute(
                "INSERT OR REPLACE INTO files (client_id, file_name, path_name, verified) VALUES (?, ?, ?, ?)",
                (client_id, file_name, path_name, verified))

            # Commit the changes and close the connection
            self.conn.commit()
            self.conn.close()

    """check weather client name is exists in database"""
    def is_client_exists(self, name: str) -> bool:
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT 1 FROM clients WHERE client_name = ?", (name,))
            row = self.cursor.fetchone()
            self.conn.close()
            # Return True if a row was found, False otherwise
            return row is not None

    """check weather client id is exists in database"""
    def find_client_by_id(self, id: bytes) -> bool:
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT 1 FROM clients WHERE client_id = ?", (id,))
            row = self.cursor.fetchone()
            self.conn.close()
            # Return True if a row was found, False otherwise
            return row is not None

    def update_verified_file(self, uid: bytes, file_name: str, _verified: bool) -> bool:

        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT 1 FROM files WHERE client_id = ? AND file_name = ?", (uid, file_name))
            row = self.cursor.fetchone()
        if row is None:
            return False
        with self.lock:
            self.cursor.execute("UPDATE files SET verified = ? WHERE client_id = ? AND file_name = ?",
                                (_verified, uid, file_name))
            self.conn.commit()
            self.conn.close()
            return True
    """Update public key for client"""
    def update_public_key(self, uid: bytes, _public_key: bytes, aes_key: bytes):
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("UPDATE clients SET public_key = ?, AES_key = ? WHERE client_id = ?",
                                (_public_key, aes_key, uid))
            self.conn.commit()
            self.conn.close()

    """find the aes key by user id"""
    def get_aes_key_by_client_id(self, client_id: bytes) -> bytes:
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT AES_key FROM clients WHERE client_id = ?", (client_id,))
            row = self.cursor.fetchone()
            self.conn.close()
            # If a row was found, return the AES_key, otherwise return None
            return row[0] if row else None

    """find the public key by user id"""
    def get_public_key_by_client_id(self, client_id: bytes) -> str:
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT public_key FROM clients WHERE client_id = ?", (client_id,))
            row = self.cursor.fetchone()
            self.conn.close()
            # If a row was found, return the AES_key, otherwise return None
            return row[0] if row else None

    """Return the all clients that are in database and their details"""
    def get_clients(self):
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT * FROM clients")
            rows = self.cursor.fetchall()
            self.conn.close()
            return rows

    """Return the all files that are in database and their details"""
    def get_files(self):
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT * FROM files")
            rows = self.cursor.fetchall()
            self.conn.close()
            return rows

    """find client name by his name if not return None"""
    def find_client_name(self, id: bytes) -> str:
        with self.lock:
            self.conn = sqlite3.connect('defensive.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute("SELECT client_name FROM clients WHERE client_id = ?", (id,))
            row = self.cursor.fetchone()
            self.conn.close()
            return row[0] if row else None

