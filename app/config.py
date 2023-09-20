class Config:
    SECRET_KEY = "YOUR SECRET KEY"

    SQLALCHEMY_DATABASE_URI = "sqlite:///database/database.db"


class Development(Config):
    DEBUG = True


class Production(Config):
    DEBUG = False
