from fastapi import FastAPI, Depends, HTTPException,BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi_mail import FastMail, MessageSchema
from pydantic import BaseModel
from fastapi import Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import jwt, JWTError
from database import Base, engine, get_db
from models import User
from config import conf, settings
from auth import hash_password, verify_password, create_access_token
from fastapi import Query
from fastapi.responses import HTMLResponse
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
load_dotenv()
Base.metadata.create_all(bind=engine)
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")



import os

config = Config(".env")
oauth = OAuth(config)

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

from fastapi import BackgroundTasks
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"]
)

@app.post("/register")
async def register(user: RegisterRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")


    new_user = User(username=user.username, email=user.email, hashed_password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    payload = {
            "user_id": new_user.id,
            "exp": datetime.utcnow() + timedelta(hours=1)  
        }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    link = f"http://localhost:8000/verify?token={token}"

    html_body = f"""
    <html>
      <body>
        <h2>Welcome, {user.username} 👋</h2>
        <p>Please verify your email by clicking the button below:</p>
        <a href="{link}" style="
          display:inline-block;
          padding:10px 20px;
          background-color:#4CAF50;
          color:white;
          text-decoration:none;
          border-radius:5px;
          font-weight:bold;
        ">
          Verify Email
        </a>
        <p>This link will expire in 1 hour.</p>
      </body>
    </html>
    """
    message = MessageSchema(
        subject="Verify your email",
        recipients=[user.email],
        body=html_body,
        subtype="html"
    )

    fm = FastMail(conf)
    background_tasks.add_task(fm.send_message, message)  

    return {"msg": "Registration successful! Check your email to verify."}


@app.get("/verify", response_class=HTMLResponse)
async def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            return "Invalid token"

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return "User not found"

        if user.is_verified:
            return "User already verified"

        user.is_verified = True
        db.commit()
        return "<h3>Email verified successfully ✅</h3>"

    except jwt.ExpiredSignatureError:
        return "<h3>Verification link expired ❌</h3>"
    except jwt.InvalidTokenError:
        return "<h3>Invalid token ❌</h3>"

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    token_data = {"sub": user.username}
    access_token = jwt.encode(token_data, settings.SECRET_KEY, algorithm="HS256")

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
def protected(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
        return {"msg": f"Hello {email}, you are authorized!"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")



@app.get("/login/google")
async def google_login(request: Request):
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return await google.authorize_redirect(request, redirect_uri)



@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await google.authorize_access_token(request)

    resp = await google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
    user_info = resp.json()

    email = user_info['email']
    username = user_info.get('name', email.split("@")[0])

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            username=username,
            email=email,
            hashed_password=None,
            is_verified=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    access_token = jwt.encode(
        {"sub": user.username, "exp": datetime.utcnow() + timedelta(hours=1)},
        settings.SECRET_KEY,
        algorithm="HS256"
    )

    return {"access_token": access_token, "token_type": "bearer"}
