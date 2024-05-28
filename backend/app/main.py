import os
import json
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc
from datetime import datetime, timedelta
from datetime import timezone 
from typing import List, Optional
from . import models, schemas
from .database import SessionLocal, engine


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(fake_db, username: str, password: str):
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if username == admin_email and verify_password(password, get_password_hash(admin_password)):
        return {"username": admin_email}
    return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

async def get_current_active_user(current_user: schemas.TokenData = Depends(get_current_user)):
    if current_user.username != os.getenv("ADMIN_EMAIL"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(None, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/hosts", response_model=schemas.HostDB)
async def create_host(host: schemas.HostCreate, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_active_user)):
    db_host = models.Host(**host.model_dump())
    db.add(db_host)
    db.commit()
    db.refresh(db_host)
    return db_host

@app.get("/hosts", response_model=List[schemas.HostDB])
async def read_hosts(
    response: Response,
    db: Session = Depends(get_db),
    current_user: schemas.TokenData = Depends(get_current_active_user),
    range: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    filter: Optional[str] = Query(None)
):
    query = db.query(models.Host)

    if filter:
        filter_params = json.loads(filter)
        for key, value in filter_params.items():
            query = query.filter(getattr(models.Host, key).ilike(f"%{value}%"))

    if sort:
        sort_field, sort_order = json.loads(sort)
        if sort_order == "ASC":
            query = query.order_by(asc(getattr(models.Host, sort_field)))
        else:
            query = query.order_by(desc(getattr(models.Host, sort_field)))

    if range:
        range_start, range_end = json.loads(range)
        query = query.offset(range_start).limit(range_end - range_start + 1)
        total = db.query(models.Host).count()
        response.headers["Content-Range"] = f"hosts {range_start}-{range_end}/{total}"

    hosts = query.all()
    return hosts

@app.delete("/hosts/{host_id}", response_model=schemas.HostDB)
async def delete_host(host_id: int, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_active_user)):
    db_host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if db_host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    db.delete(db_host)
    db.commit()
    return db_host

@app.post("/subnets", response_model=schemas.SubnetDB)
async def create_subnet(subnet: schemas.SubnetCreate, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_active_user)):
    db_subnet = models.Subnet(**subnet.model_dump())
    db.add(db_subnet)
    db.commit()
    db.refresh(db_subnet)
    return db_subnet

@app.get("/subnets", response_model=List[schemas.SubnetDB])
async def read_subnets(
    response: Response,
    db: Session = Depends(get_db),
    current_user: schemas.TokenData = Depends(get_current_active_user),
    range: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    filter: Optional[str] = Query(None)
):
    query = db.query(models.Subnet)

    if filter:
        filter_params = json.loads(filter)
        for key, value in filter_params.items():
            query = query.filter(getattr(models.Subnet, key).ilike(f"%{value}%"))

    if sort:
        sort_field, sort_order = json.loads(sort)
        if sort_order == "ASC":
            query = query.order_by(asc(getattr(models.Subnet, sort_field)))
        else:
            query = query.order_by(desc(getattr(models.Subnet, sort_field)))

    if range:
        range_start, range_end = json.loads(range)
        query = query.offset(range_start).limit(range_end - range_start + 1)
        total = db.query(models.Subnet).count()
        response.headers["Content-Range"] = f"subnets {range_start}-{range_end}/{total}"

    subnets = query.all()
    return subnets

@app.delete("/subnets/{subnet_id}", response_model=schemas.SubnetDB)
async def delete_subnet(subnet_id: int, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_active_user)):
    db_subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if db_subnet is None:
        raise HTTPException(status_code=404, detail="Subnet not found")
    db.delete(db_subnet)
    db.commit()
    return db_subnet

@app.post("/dangerous-cves", response_model=schemas.DangerousCVEDB)
async def create_dangerous_cve(cve: schemas.DangerousCVECreate, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_active_user)):
    db_cve = models.DangerousCVE(**cve.model_dump())
    db.add(db_cve)
    db.commit()
    db.refresh(db_cve)
    return db_cve

@app.get("/dangerous-cves", response_model=List[schemas.DangerousCVEDB])
async def read_dangerous_cves(
    response: Response,
    db: Session = Depends(get_db),
    current_user: schemas.TokenData = Depends(get_current_active_user),
    range: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    filter: Optional[str] = Query(None)
):
    query = db.query(models.DangerousCVE)

    if filter:
        filter_params = json.loads(filter)
        for key, value in filter_params.items():
            query = query.filter(getattr(models.DangerousCVE, key).ilike(f"%{value}%"))

    if sort:
        sort_field, sort_order = json.loads(sort)
        if sort_order == "ASC":
            query = query.order_by(asc(getattr(models.DangerousCVE, sort_field)))
        else:
            query = query.order_by(desc(getattr(models.DangerousCVE, sort_field)))

    if range:
        range_start, range_end = json.loads(range)
        query = query.offset(range_start).limit(range_end - range_start + 1)
        total = db.query(models.DangerousCVE).count()
        response.headers["Content-Range"] = f"dangerous-cves {range_start}-{range_end}/{total}"

    cves = query.all()
    return cves

@app.delete("/dangerous-cves/{cve_id}", response_model=schemas.DangerousCVEDB)
async def delete_dangerous_cve(cve_id: int, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_active_user)):
    db_cve = db.query(models.DangerousCVE).filter(models.DangerousCVE.id == cve_id).first()
    if db_cve is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    db.delete(db_cve)
    db.commit()
    return db_cve
