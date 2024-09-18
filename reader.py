import sqlite3

def read_db(db_path):
    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Get a list of all tables in the database
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = c.fetchall()

    print("Tables in the database:")
    for table in tables:
        table_name = table[0]
        print(f"\nTable: {table_name}")
        
        # Get all rows from the table
        c.execute(f"SELECT * FROM {table_name}")
        rows = c.fetchall()
        
        # Get column names
        c.execute(f"PRAGMA table_info({table_name})")
        columns = [desc[1] for desc in c.fetchall()]
        
        # Display column names and rows
        print(f"Columns: {columns}")
        for row in rows:
            print(row)

    conn.close()

# Path to your SQLite database
db_path = 'database.db'

# Call the function to read and display the contents of the database
read_db(db_path)
