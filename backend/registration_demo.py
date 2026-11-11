
from getpass import getpass

from backend.app.database.user_repository import (
    register_user,
    authenticate_user
)


def main():

    print("=== SECUREVAULT USER REGISTRATION ===")

    username = input("Create username: ").strip()
    password = getpass("Create practice password: ")

    try:
        user_id = register_user(username, password)

        print("USER REGISTERED SUCCESSFULLY")
        print("User ID:", user_id)

    except ValueError as error:
        print("REGISTRATION FAILED:", error)
        return

    print()
    print("=== SECUREVAULT LOGIN TEST ===")

    login_password = getpass("Enter password again: ")

    user = authenticate_user(username, login_password)

    if user is not None:
        print("AUTHENTICATION SUCCESSFUL")
        print("Welcome:", user["username"])

    else:
        print("AUTHENTICATION FAILED")


if __name__ == "__main__":
    main()
