"""Rules applied before automatic target requests. Offline imports use Scope only."""
import re
from urllib.parse import parse_qsl, unquote, urlsplit
from .core import Scope, SECRET

DENIED_SEGMENTS = re.compile(r'(?:^|[/_.-])(?:logout|signout|delete|remove|revoke|destroy|reset|activate|verify|confirm|send|trigger|execute|run|restart|shutdown|reboot|purge|flush|migrate|rebuild|restore|transfer|checkout|payment|refund|unsubscribe|job)(?:$|[/_.-]|[0-9])', re.I)
DENIED_EXTENSIONS = ('.iso', '.sql', '.dump', '.mp4')
COSTLY = re.compile(r'(?:export|download|backup|report)', re.I)
ACTION_KEYS = {'action', 'act', 'cmd', 'command', 'operation', 'op', 'task', 'do'}
SAFE_ACTIONS = {'view', 'list', 'get', 'read', 'show', 'search'}
SIZE_KEYS = {'limit', 'pagesize', 'page_size', 'count', 'size', 'per_page', 'perpage', 'length'}


class PolicyDenied(ValueError):
    pass


class NetworkPolicy:
    def __init__(self, scope, reviewed_paths=(), allow_user_actions=False, allowed_ports=(80,443,8080,8443)):
        self.scope = scope if isinstance(scope, Scope) else Scope(scope)
        self.reviewed_paths = set(reviewed_paths)
        if any(not p.startswith('/') or '?' in p or '#' in p for p in self.reviewed_paths):
            raise ValueError('Reviewed paths must be exact absolute paths')
        self.allow_user_actions = allow_user_actions
        self.allowed_ports = set(allowed_ports)

    def reason(self, url, method='GET', manual=False):
        try:
            parsed = urlsplit(url)
            if not self.scope.allows(url):
                return 'out_of_scope_or_invalid_authority'
            if parsed.port is not None and parsed.port not in self.allowed_ports:
                return 'unreviewed_port'
            if any(ord(c) < 33 for c in url) or len(url) > 4096:
                return 'invalid_or_excessive_url'
            path = parsed.path or '/'
            for _ in range(3):
                decoded = unquote(path)
                if decoded == path:
                    break
                path = decoded
            if '\\' in path or any(x in ('.', '..') for x in path.split('/')):
                return 'ambiguous_path'
            reviewed = manual and path in self.reviewed_paths
            if method.upper() not in ('GET', 'HEAD') and not (reviewed and self.allow_user_actions):
                return 'non_read_method'
            if not reviewed and (DENIED_SEGMENTS.search(path) or path.lower().endswith(DENIED_EXTENSIONS)):
                return 'state_changing_or_costly_path'
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                k = key.lower()
                v = unquote(value).lower()
                if SECRET.search(k) and not reviewed:
                    return 'credential_or_one_time_query'
                if k in ACTION_KEYS and v not in SAFE_ACTIONS and not reviewed:
                    return 'unreviewed_action_query'
                if k in SIZE_KEYS and (not v.isdecimal() or int(v) > 100):
                    return 'excessive_or_unknown_page_size'
                if len(value) > 256 or any(c in value for c in '<>\x00\r\n'):
                    return 'unreviewed_query_value'
            return None
        except (ValueError, UnicodeError):
            return 'malformed_url'

    @staticmethod
    def is_costly(url):
        return bool(COSTLY.search(urlsplit(url).path))

    def check(self, url, method='GET', manual=False):
        reason = self.reason(url, method, manual)
        if reason:
            raise PolicyDenied(reason)


def scope_from_file(path):
    return Scope(path.read_text(encoding='utf-8').splitlines())
