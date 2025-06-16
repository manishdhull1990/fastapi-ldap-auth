from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ldap_host: str
    base_dn: str
    user_dn_template: str = "uid={username},ou=users,{base_dn}"
    group_search_base: str

    jwt_secret_key:str
    jwt_algorithm:str = "HS256"
    jwt_expire_minutes:int = 1
    jwt_expire_expire_days:int = 7
    model_config = SettingsConfigDict(env_file=".env")

    db_user:str
    db_password:str
    db_host:str
    db_port:str
    db_name:str

settings = Settings()