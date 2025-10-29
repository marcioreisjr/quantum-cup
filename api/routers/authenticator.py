import os
from fastapi import Depends
from jwtdown_fastapi.authentication import Authenticator
from queries.users import AccountQueries
from models.users import AccountOutWithHashedPassword, AccountOut


class CoffeeAuthenticator(Authenticator):
    async def get_account_data(
        self,
        username: str,
        account_getter,
    ):
        # Use your repo to get user by username
        return account_getter.get_one_by_username(username)

    def get_account_getter(
        self,
        account_getter: AccountQueries = Depends(),
    ):
        return account_getter

    def get_hashed_password(self, account_data):
        # Return the encrypted password
        return account_data.hashed_password

    def get_account_data_for_cookie(
        self, account_data
    ):
        # Return the username and the data for the cookie.
        # You must return TWO values from this method.
        return account_data.username, account_data.dict(exclude={'hashed_password'})


authenticator = CoffeeAuthenticator(os.environ["SIGNING_KEY"])
