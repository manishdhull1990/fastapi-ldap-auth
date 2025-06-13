from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ldap_host: str
    base_dn: str
    user_dn_template: str = "uid={username},ou=users,{base_dn}"
    group_search_base: str

    jwt_secret_key:str
    jwt_algorithm:str = "HS256"
    jwt_expire_minutes:int =30
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()