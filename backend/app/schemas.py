from pydantic import BaseModel

class HostCreate(BaseModel):
    hostname: str
    ip: str
    type: str

class HostDB(HostCreate):
    id: int


class SubnetCreate(BaseModel):
    subnet: str
    env: str
    name: str

class SubnetDB(SubnetCreate):
    id: int

class DangerousCVECreate(BaseModel):
    cve_id: str
    comment: str

class DangerousCVEDB(DangerousCVECreate):
    id: int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None