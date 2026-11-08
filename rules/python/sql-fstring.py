def find(cur, name, city):
    # ruleid: python.sql-fstring
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: python.sql-fstring
    cur.execute("SELECT * FROM users WHERE city = '%s'" % city)
    # ruleid: python.sql-fstring
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    q = "DELETE FROM users WHERE name = '{}'".format(name)
    # ruleid: python.sql-fstring
    cur.execute(q)
    # ok: python.sql-fstring
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    # ok: python.sql-fstring
    cur.execute("SELECT 1")
