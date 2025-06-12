from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError
from .config import settings

def authenticate_user(username:str, password:str)->bool:
    user_dn = settings.user_dn_template.format(username=username,base_dn=settings.base_dn)
    server = Server(settings.ldap_host, get_info=ALL)

    try:
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        conn.unbind()
        return True
    except LDAPBindError:
        return False