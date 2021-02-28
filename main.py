import bcrypt
from cryptography.fernet import Fernet
import sqlite3
from sqlite3 import OperationalError
import mysql.connector
import time
import random
import string
from env import secret_keys


# Sqlite connection
conn = sqlite3.connect('UserAccounts.db')
cur = conn.cursor()

# MySQL connection
main_conn = mysql.connector.connect(
    host=secret_keys['mySQL Host'],
    user=secret_keys['mySQL User'],
    password=secret_keys['mySQL Password'],
    database=secret_keys['mySQL DB'])
main_cur = main_conn.cursor()

# TODO for matters of safety a system with one key for each user might not be indicated
# TODO instead a key for each password could actually be more secure
# TODO implement one key for each password

# SQL to create the 2 main tables in a separate database via MySQL
# main_cur.execute(f"CREATE TABLE IF NOT EXISTS Users (id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, "
#             f"name VARCHAR(255) NOT NULL UNIQUE,"
#             f"master_pwd TEXT NOT NULL )")
# main_cur.execute(f"CREATE TABLE IF NOT EXISTS Tokens (id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, "
#             f"user_id INTEGER NOT NULL, pwd_id INTEGER, "
#             f"token TEXT NOT NULL, "
#             f"FOREIGN KEY (user_id) REFERENCES Users(id))")
# main_conn.commit()


# Password generator for added security
class SuperPassword:
    alphabet = string.ascii_letters
    numbers = string.digits
    symbols = string.punctuation
    hexadecimal = string.hexdigits

    @staticmethod
    def generate_password(vocabulary, num):
        """This function generates a random alphanumeric password. Default length is 18 but longer can
        be generated via the parameter num"""

        gen_password = ''
        for _ in range(num):
            gen_password += random.choice(vocabulary)
        return gen_password

    def normal(self, num: int = 18):
        """Generates a normal alphabetic password with lowercase and uppercase letters"""

        return self.generate_password(self.alphabet, num)

    def medium(self, num: int = 18):
        """Generates a stronger password made of alphabet letters (a-z)(A-Z) and numbers (0-9)"""

        voc = self.alphabet + self.numbers
        return self.generate_password(voc, num)

    def hex(self, num: int = 18):
        """Generates a password made of hexadecimal characters [(a-f)(A-F)(0-9)]"""

        return self.generate_password(self.hexadecimal, num)

    def strong(self,  num: int = 18):
        """Generates a strong password made of alphabet letters (a-z)(A-Z), numbers (0-9)
        and punctuation !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ """

        voc = self.alphabet + self.numbers + self.symbols
        return self.generate_password(voc, num)


# Basic CRUD operations on DB, it works only after access
def create(user, account, password, alias):
    """Create a new record in the db/table of the user. Alias is an alternative way to retrieve
    the password once it's saved. See read()"""

    main_cur.execute(f"SELECT id FROM Users WHERE name='{user}'")
    select_user = main_cur.fetchone()
    main_cur.execute(f"SELECT token FROM Tokens WHERE user_id={select_user[0]}")
    key = main_cur.fetchone()[0].encode('utf-8')
    cipher_suite = Fernet(key)
    enc_password = cipher_suite.encrypt(password.encode('utf-8'))

    create_record = f"INSERT INTO {user} (account_name, password, alias) " \
                    f"VALUES ('{account}', '{enc_password.decode('utf-8')}', '{alias.lower()}')"
    cur.execute(create_record)
    conn.commit()

    print('Record created!')
    actions(user)
    return


def delete(user, account, master_password, alias):
    """Simply delete a record from the table of the user. To do so the user needs to have the master password"""

    main_cur.execute(f"SELECT master_pwd FROM Users WHERE name='{user}'")
    result = main_cur.fetchone()

    if not bcrypt.checkpw(master_password.encode('utf-8'), result[0].encode('utf-8')):
        print('Master password is not correct!')
        return
    if len(alias) == 0:
        try:
            cur.execute(f"DELETE FROM {user} WHERE account_name='{account}'")
            conn.commit()
        except OperationalError as op:
            print(op)
            return
    else:
        cur.execute(f"DELETE FROM {user} WHERE alias='{alias}' ")
        conn.commit()

    print('Record deleted!')
    actions(user)
    return


def update(user, account, password):
    """Enables a user to update any row and record. If the change affects the master account and password, the
    master password needs to be provided"""

    try:
        cur.execute(f"SELECT id FROM {user} WHERE account_name='{account}'")
    except OperationalError:
        print(f'No account named {account} found')
        return
    main_cur.execute(f"SELECT * FROM Users WHERE name='{user}'")
    select_user = main_cur.fetchone()

    if user == account:
        print('You are trying to update the Master password.')
        master_key = input('Please enter the Master Password:  ')
        if not bcrypt.checkpw(master_key.encode('utf-8'), select_user[2].encode('utf-8')):
            print('Master password is not correct!')
            return
        hashed_pwd = bcrypt.hashpw(password.encode('UTF-8'), bcrypt.gensalt()).decode('utf-8')
        main_cur.execute(f"UPDATE Users SET master_pwd='{hashed_pwd}' WHERE name='{user}'")
        main_conn.commit()

        print('Password updated!')
    else:
        main_cur.execute(f"SELECT token FROM Tokens WHERE user_id={select_user[0]}")
        select_key = main_cur.fetchone()[0]
        key = select_key.encode('utf-8')
        cipher_suite = Fernet(key)
        enc_password = cipher_suite.encrypt(password.encode('utf-8'))
        cur.execute(f"UPDATE {user} SET password='{enc_password.decode('utf-8')}' WHERE account_name='{account}'")
        print('Password updated!')
        conn.commit()

    actions(user)
    return


def read(user, account, master_password):
    """Allows to retrieve a record from the table of the user. The master password needs to be provided.
    In case the alias is provided the search will be executed via alias, otherwise the account name will
    be used. One of the 2 must be given"""

    main_cur.execute(f"SELECT * FROM Users WHERE name='{user}'")
    select_user = main_cur.fetchone()

    if not bcrypt.checkpw(master_password.encode('utf-8'), select_user[2].encode('UTF-8')):
        print('Master password is not valid!')
        return

    user_search = cur.execute(f"SELECT * FROM {user} where account_name='{account}'").fetchone()
    main_cur.execute(f"SELECT token FROM Tokens WHERE user_id={select_user[0]}")
    select_key = main_cur.fetchone()[0]

    user_pwd = user_search[2].encode('utf-8')
    key = select_key.encode('utf-8')
    cipher_suite = Fernet(key)
    decrypted_pwd = cipher_suite.decrypt(user_pwd)

    response = {
        'account_name': account,
        'password': decrypted_pwd.decode('utf-8'),
        'alias': user_search[3]
    }

    print(response)
    actions(user)
    return


def actions(account):
    """Group of CRUD actions to be executed in the DB according to user choice. Quit is also included"""

    while True:
        choices = 'crudq'
        user_choice = input('Select action:\nCreate (C) Read (R) Update (U) Delete (D) or Quit (Q)\n')
        if user_choice.lower() not in choices:
            continue
        elif user_choice.lower() == 'c':
            record_account = input('Name of the account (required).'
                                   'You will use this to retrieve a password: ')
            password = input('Password (required):  ')
            alias = input('Create an alias. A generic name for the account. (not required):  ')
            create(account, record_account, password, alias)
        elif user_choice.lower() == 'u':
            record_account = input('Name of the account to update(required):  ')
            new_password = input('New Password (required):  ')
            update(account, record_account, new_password)
        elif user_choice.lower() == 'r':
            record_account = input('Name of the account to look up:  ')
            master_key = input('Master Password (required):  ')
            read(account, record_account, master_key)
        elif user_choice.lower() == 'd':
            record_account = input('Name of the account to delete:  ')
            master_key = input('Master Password (required):  ')
            alias = input('Use the alias of the account. If you haven\'t provided the name of the account'
                          ' you can use the alias but one of the 2 must be used:  ')
            delete(account, record_account, master_key, alias)
        elif user_choice.lower() == 'q':
            main_conn.close()
            conn.close()
            print('Bye Bye')
            time.sleep(2)
            quit()


def access_account(where_from=False, user=None):
    """To access the account you need to provide username and master password. If coming from registration
    it will be included in the process, otherwise a direct access will need the entire process"""

    if not where_from:
        while True:
            account = input('Please enter your username (required):  ')
            password = input('Master Password (required):  ')

            main_cur.execute(f"SELECT master_pwd FROM Users WHERE name='{account}'")
            result = main_cur.fetchone()  # tuple
            if result is None:
                print(f'The username {account} is not valid')
                continue

            if bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                actions(account)
            else:
                print('Password is not correct!')
                continue
    else:
        actions(user)


def password_complexity():
    pwd_complexity = input('How many characters would you like?\n'
                           '(if blank default is 18)  ')
    if len(pwd_complexity) == 0:
        length = 18
    else:
        try:
            length = int(pwd_complexity)
        except ValueError:
            print(f"{pwd_complexity} not computable. Number is set to 18")
            length = 18
    return length


def password_gen():
    password = SuperPassword()
    master_pwd = ''
    print('You can choose what kind of password you want')
    while True:
        pwd_type = input('types:  Normal (N) Medium (M) Hexadecimal (H) or Strong (S)\n')
        if pwd_type.lower() == 'n':
            length = password_complexity()
            master_pwd = password.normal(num=length)
        elif pwd_type.lower() == 'm':
            length = password_complexity()
            master_pwd = password.medium(num=length)
        elif pwd_type.lower() == 'h':
            length = password_complexity()
            master_pwd = password.hex(num=length)
        elif pwd_type.lower() == 's':
            length = password_complexity()
            master_pwd = password.strong(num=length)
        else:
            print(f"No selection {pwd_type} available")
            continue

        print(f"The generated password is: {master_pwd}")
        yes_or_no = input('Do you want to keep it (Y/N)?  ')
        if yes_or_no.lower() == 'n':
            continue
        elif yes_or_no.lower() == 'y':
            print('You might want to note it somewhere safe.\nWhen done press any key.')
            input()
            break
        else:
            print(f"No selection {yes_or_no} available")
            continue
    # print(master_pwd) DEBUGGING
    return master_pwd


def main():
    """Main logic behind the password manager. To start with Create Mode or Access Mode"""

    while True:
        selection = input('Please select one of the following options: \n'
                          'Create Account (C) or Access Account(A) or Quit (Q)  ')

        # Create account
        if selection.lower() == 'c':
            username = input('Enter a username:  ')
            print('You can either type your own password or generate one')
            pwd_selection = input('Type (T) or Generate (G)')
            if pwd_selection.lower() == 't':
                master_pwd = input('Enter a master password (you will use this password '
                                   'to access all your stored passwords):  ')
            elif pwd_selection.lower() == 'g':  # generate password
                master_pwd = password_gen()
            else:
                print(f"No selection {pwd_selection} available")
                continue

            if len(master_pwd) == 0:
                print('Password is required')
                continue
            try:
                cur.execute(f'CREATE TABLE {username} (id INTEGER PRIMARY KEY AUTOINCREMENT,'
                            f' account_name VARCHAR(255) NOT NULL, password TEXT NOT NULL, alias VARCHAR(64))')
                conn.commit()

            except OperationalError as op:
                print(f'Username {username} already exists')
                time.sleep(2)
                continue

            hashed_master = bcrypt.hashpw(master_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            main_cur.execute(f"INSERT INTO Users (name, master_pwd) VALUES ('{username}', '{hashed_master}')")
            main_conn.commit()
            main_cur.execute(f"SELECT id FROM Users WHERE name='{username}'")
            select_user = main_cur.fetchone()

            key = Fernet.generate_key()
            main_cur.execute(f"INSERT INTO Tokens (user_id, token) VALUES ({select_user[0]}, '{key.decode('utf-8')}')")
            main_conn.commit()
            main_conn.close()

            print('Your account was created.\nYou can either relaunch this app or select Access')

            while True:
                access = input('Access: Y/N?  ')
                if access.lower() == 'n':
                    main_conn.close()
                    conn.close()
                    print('Bye Bye')
                    time.sleep(2)
                    quit()
                elif access.lower() == 'y':
                    access_account(True, username)
                else:
                    continue
        elif selection.lower() == 'a':
            access_account()
        elif selection.lower() == 'q':
            main_conn.close()
            conn.close()
            print('Bye Bye')
            time.sleep(2)
            quit()
        else:
            print(f'No selection {selection} available')
            time.sleep(2)
            continue


if __name__ == '__main__':
    main()
