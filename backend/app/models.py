from sqlalchemy import Column, Integer, String
from .database import Base

class Host(Base):
    __tablename__ = 'hosts'
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    ip = Column(String, index=True)
    type = Column(String)

class Subnet(Base):
    __tablename__ = 'subnets'
    id = Column(Integer, primary_key=True, index=True)
    subnet = Column(String, index=True)
    env = Column(String)
    name = Column(String)

class DangerousCVE(Base):
    __tablename__ = 'dangerous_cves'
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True)
    comment = Column(String)
