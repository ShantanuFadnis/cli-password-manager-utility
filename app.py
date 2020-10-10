from typing import Tuple, NoReturn, List, Optional, Dict
import sys
import bcrypt
from uuid import uuid1


def print_usage():
    print("%-20s %-40s" % ("Command", "Description"))
    print("%-20s %-40s" % ("ls", "List accounts from the database"))
    print("%-20s %-40s" % ("gen", "Generate a password for an account"))
    print("%-20s %-40s" % ("ret", "Retrieve a password for an account"))
    print("%-20s %-40s" % ("upd", "Regenerate a password for an existing account"))


class FileHandler:
    _fixed_record_length = 150
    _datafile_name = ".psmdatadb72c60a-0afd-11eb-983b-c4b301c7d3e9"

    @classmethod
    def populate_store(cls):
        try:
            with open(cls._datafile_name, "rb") as f:
                while True:
                    record = f.read(cls._fixed_record_length)
                    if len(record) == 0:
                        break
                    credentials = eval(record.decode("utf-8").strip())
                    PasswordManager.password_store[credentials[0].lower()] = credentials[1]
        except FileNotFoundError:
            f = open(cls._datafile_name, "w")
            f.close()

    @classmethod
    def add(cls, credentials: Tuple) -> NoReturn:
        with open(cls._datafile_name, "ab") as f:
            f.write(bytes(str(credentials).ljust(cls._fixed_record_length), "utf-8"))

    @classmethod
    def update(cls, credentials: Tuple) -> NoReturn:
        with open(cls._datafile_name, "rb+") as f:
            while True:
                record = f.read(cls._fixed_record_length)
                if len(record) == 0:
                    break
                record = eval(record.decode("utf-8").strip())
                faccount = record[0]
                if faccount.lower() == credentials[0].lower():
                    f.seek(-cls._fixed_record_length, 1)
                    f.write(bytes(str(credentials).ljust(cls._fixed_record_length), "utf-8"))
                    break


class PasswordManagerException(Exception):
    def __init__(self, message):
        self.message = message


class PasswordManager:
    password_store = dict()

    @classmethod
    def generate_pw(cls, account: str) -> Optional[str]:
        if account.lower() in cls.password_store:
            raise PasswordManagerException(f"Password for account {account} already exists.")
        hashed_pw = cls.get_hashed_pw()
        credential = (account, hashed_pw)
        FileHandler.add(credential)
        return hashed_pw

    @classmethod
    def get_hashed_pw(cls):
        return bcrypt.hashpw(str(uuid1()).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @classmethod
    def get_account(cls) -> str:
        accounts = list(PasswordManager.get_passwords().keys())
        if len(accounts) == 0:
            raise PasswordManagerException("No accounts found in the database.")
        temp = dict()
        for n, account in enumerate(accounts, start=1):
            print(f"{n}. {account}")
            temp[n] = account
        while True:
            account_srno = input("Enter an account from the list above: ")
            try:
                account_srno = int(account_srno)
            except ValueError:
                print(f"Invalid choice: {account_srno}")
                continue
            if account_srno not in temp:
                print(f"Invalid choice: {account_srno}")
                continue
            break
        return temp[account_srno].lower()

    @classmethod
    def get_pw(cls, account):
        credentials = PasswordManager.get_passwords()
        return credentials[account.lower()]

    @classmethod
    def update_pw(cls, account):
        hashed_pw = cls.get_hashed_pw()
        credentials = (account, hashed_pw)
        FileHandler.update(credentials)
        return hashed_pw

    @classmethod
    def get_passwords(cls) -> Dict:
        return PasswordManager.password_store


class ArgumentWrapper:
    @classmethod
    def ls(cls) -> Optional[List]:
        return list(PasswordManager.get_passwords().keys())

    @classmethod
    def gen(cls) -> Optional[str]:
        account = input("Enter an account: ")
        return PasswordManager.generate_pw(account)

    @classmethod
    def ret(cls) -> Optional[str]:
        account = PasswordManager.get_account()
        return PasswordManager.get_pw(account)

    @classmethod
    def upd(cls) -> Optional[str]:
        account = PasswordManager.get_account()
        return PasswordManager.update_pw(account)


try:
    arguments = sys.argv[1:]
    if len(arguments) == 0:
        print_usage()
        sys.exit()

    FileHandler.populate_store()
    action = arguments[0]
    if action == "ls":
        accounts = ArgumentWrapper.ls()
        if len(accounts) == 0:
            print("No accounts found in the database.")
            sys.exit()
        print("%-25s" % "Accounts")
        for n, account in enumerate(accounts, start=1):
            print("%s. %-25s" % (n, account))

    elif action == "gen":
        password = ArgumentWrapper.gen()
        print(password)

    elif action == "ret":
        password = ArgumentWrapper.ret()
        print(password)

    elif action == "upd":
        password = ArgumentWrapper.upd()
        print("Password successfully updated.")
        print(password)

    else:
        print(f"Invalid action: {action}")

except PasswordManagerException as err:
    print(err)
