from ldap3 import Server, Connection, ALL, SUBTREE
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

def get_user_group(username:str)->str |None:
    user_dn = settings.user_dn_template.format(username=username, base_dn=settings.base_dn)
    server = Server(settings.ldap_host, get_info=ALL)

    with Connection(server, auto_bind=True) as conn:
        search_filter = f"(member={user_dn})"
        conn.search(
            search_base=settings.group_search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["cn"]
        )

        if conn.entries:
            return conn.entries[0]["cn"].value
        return None