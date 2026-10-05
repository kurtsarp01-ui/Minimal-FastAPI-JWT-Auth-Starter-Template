from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from auth import hash_password, verify_password, create_access_token, SECRET_KEY, ALGORITHM

app = FastAPI(title="Minimal FastAPI JWT Auth")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Basit demo veritabanı (bellek içi)
fake_users_db = {}

@app.post("/register")
def register(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username in fake_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    fake_users_db[form_data.username] = {
        "username": form_data.username,
        "password": hash_password(form_data.password)
    }
    return {"message": "User registered successfully"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@app.get("/me")
def read_users_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user, "status": "Authenticated"}