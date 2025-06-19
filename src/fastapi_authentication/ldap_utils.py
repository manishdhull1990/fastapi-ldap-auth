from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPException
from .config import settings

class LDAPAuthError(Exception):
    """Generic LDAP error for higher-level handling."""
    pass

def authenticate_user(username:str, password:str)->bool:
    """
    Bind to LDAP with given credentials.
    Returns True if bind succeeds; False if credentials invalid.
    Raises LDAPAuthError on other LDAP errors.
    """
    user_dn = settings.user_dn_template.format(username=username,base_dn=settings.base_dn)
    server = Server(settings.ldap_host, get_info=ALL)

    try:
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        conn.unbind()
        return True
    except LDAPBindError:
        # Invalid credentials → return False, route will log
        return False
    except LDAPException as e:
        # Other LDAP errors (connectivity, schema, etc.)
        raise LDAPAuthError(f"LDAP bind/search error for user {username}: {e}") from e
    except Exception as e:
        raise LDAPAuthError(f"Unexpected error during LDAP auth for user {username}: {e}") from e


def get_user_group(username:str)->str |None:
    """
    Search LDAP groups for the given user DN.
    Returns group name if found, else None.
    Raises LDAPAuthError on LDAP errors.
    """
    user_dn = settings.user_dn_template.format(username=username, base_dn=settings.base_dn)
    server = Server(settings.ldap_host, get_info=ALL)
    try:
        with Connection(server, auto_bind=True) as conn:
            search_filter = f"(member={user_dn})"
            conn.search(
                search_base=settings.group_search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["cn"]
            )

            if conn.entries:
                group_name = conn.entries[0]["cn"].value
                return group_name
            else:
                return None
    except LDAPException as e:
        raise LDAPAuthError(f"LDAP search error for user {username}: {e}") from e
    except Exception as e:
        raise LDAPAuthError(f"Unexpected error during LDAP group fetch for user {username}: {e}") from e