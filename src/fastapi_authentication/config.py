from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ldap_host: str
    base_dn: str
    user_dn_template: str = "uid={username},ou=users,{base_dn}"
    group_search_base: str

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()