from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response,
    HTTPException,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from models.users import (
    AccountToken,
    AccountIn,
    AccountForm,
    AccountOut,
    Error,
)
from queries.users import AccountQueries, DuplicateAccountError
from .authenticator import authenticator

router = APIRouter()


@router.post("/signup", response_model=dict)
async def signup(
    user: AccountIn,
    request: Request,
    response: Response,
    repo: AccountQueries = Depends(),
):
    user.password = user.password[:72]  # Truncate to 72 bytes for bcrypt
    hashed_password = authenticator.hash_password(user.password)
    try:
        account = repo.create(user, hashed_password)
    except DuplicateAccountError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create an account with those credentials",
        )
    del account["hashed_password"]
    # form = type('Form', (), {'username': user.username, 'password': user.password})()
    # accounts_getter = authenticator.get_account_getter(repo)
    # token = await authenticator.login(response, request, form, accounts_getter)
    # return AccountToken(account=AccountOut(**account), **token.dict())
    return {"message": "ok"}


@router.get("/token", response_model=AccountToken | None)
async def get_token(
    request: Request,
    account: AccountOut = Depends(authenticator.try_get_current_account_data),
) -> AccountToken | None:
    if account and authenticator.cookie_name in request.cookies:
        return {
            "access_token": request.cookies[authenticator.cookie_name],
            "type": "Bearer",
            "account": account,
        }
