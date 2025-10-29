from models.users import AccountIn, AccountOutWithHashedPassword
from .client import Queries


# DATABASE_URL: str | None = os.environ.get("DATABASE_URL")


class DuplicateAccountError(ValueError):
    pass


# Class representing queries related to user accounts
class AccountQueries(Queries):
    # MongoDB collection name for accounts
    collection_name = "accounts"

    def create(self, info: AccountIn, hashed_password: str):
        """
                Create a new account in the database.

                :param info: AccountIn object containing account information
                :param hashed_password: Hashed password for the account
                :return: Created account information
                :raises DuplicateAccountError: If an account with the
        same username already exists
        """
        account = info.dict()
        # Check if an account with the same username already exists
        if self.get_one_by_username(account["username"]) is not None:
            raise DuplicateAccountError

        # Set hashed password, remove plain text password, and insert
        # the account
        account["hashed_password"] = hashed_password
        del account["password"]
        self.collection.insert_one(account)

        # Assign a string representation of the MongoDB ObjectId as the account
        # ID
        account["id"] = str(account["_id"])
        del account["_id"]
        return account

    def get_one_by_username(self, username: str):
        """
        Get an account by username.

        :param username: Username of the account
        :return: Account information or None if not found
        """
        result = self.collection.find_one({"username": username})

        # If no account is found, return None
        if result is None:
            return None

        # Assign a string representation of the MongoDB ObjectId as the account
        #  ID
        result["id"] = str(result["_id"])
        return AccountOutWithHashedPassword(**result)
