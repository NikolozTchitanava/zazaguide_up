import sqlite3

def delete_extra_admins():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Delete all admins except the one with id 1 (zagza)
    c.execute("DELETE FROM admin WHERE id != 1")

    conn.commit()
    conn.close()

    print("All extra admins deleted, only 'zagza' remains.")

# Call the function to delete extra admins
delete_extra_admins()
