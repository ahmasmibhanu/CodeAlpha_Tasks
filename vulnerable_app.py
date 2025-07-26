# app.py - Secure Code Example using Parameterized Queries

def simulate_database_query_secure(username_param):
    """
    Simulates a database query that is secure against SQL Injection
    using parameterized queries (placeholders).
    """
    # Notice the '?' or '%s' placeholder for the username.
    # The actual value for 'username_param' is passed separately.
    # This prevents malicious input from being interpreted as SQL code.
    query_template = "SELECT * FROM users WHERE username = ? AND password = 'some_password';"
    # In real Python database connectors (like sqlite3, psycopg2, mysql.connector),
    # you would pass the parameters as a tuple or list to the execute method.
    parameters = (username_param,) # Note the comma to make it a tuple, even with one item

    print(f"--- Simulated Secure Query Being Executed ---")
    print(f"Query Template: {query_template}")
    print(f"Parameters: {parameters}")
    print(f"-------------------------------------------")

    # Simulate the database handling the parameters safely
    # It will escape or properly handle the 'username_param' value.
    # Even if username_param is "' OR 1=1; --", it's treated as a literal string.
    if "OR 1=1" in username_param or "DROP TABLE" in username_param or "--" in username_param:
        print("\nNotice: Suspicious characters were detected in the *input*,")
        print("but they are treated as *data* by the parameterized query, not as executable code.")
        print("Therefore, this attack would be prevented.")
    else:
        print("\nSimulated: Secure query executed.")


def main_secure():
    print("--- Secure Login Simulation (Parameterized Query) ---")
    print("Enter a username to simulate a login check.")
    print("Try a normal username like 'admin' or 'user123'.")
    print("Then try an injection payload like: ' OR 1=1; --")
    print("Notice how the attack is prevented.")
    print("---------------------------------------------------")

    user_input = input("Enter username: ")
    simulate_database_query_secure(user_input)

if __name__ == "__main__":
    main_secure()
