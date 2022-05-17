from dataclasses import dataclass
from typing import Optional

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import tuple_row


@dataclass
class Account:
    id: int
    primary_nick: int
    password: str
    salt: str
    url: Optional[str]
    email: str
    cloak: Optional[str]
    flag_enforce: bool
    flag_secure: bool
    flag_verified: bool
    flag_cloak_enabled: bool
    flag_admin: bool
    flag_email_verified: bool
    flag_private: bool
    language: int
    last_host: Optional[str]
    last_realname: Optional[str]
    last_quit_msg: Optional[str]
    last_quit_time: Optional[int]
    reg_time: int


@dataclass
class Nickname:
    id: int
    nick: str
    account_id: int
    reg_time: int
    last_seen: Optional[int]


@dataclass
class Channel:
    id: int
    channel: str
    flag_private: bool
    flag_restricted: bool
    flag_topic_lock: bool
    flag_verbose: bool
    flag_autolimit: bool
    flag_expirebans: bool
    flag_floodserv: bool
    flag_autoop: bool
    flag_autovoice: bool
    flag_leaveops: bool
    flag_autosave: bool
    description: str
    url: Optional[str]
    email: Optional[str]
    entrymsg: Optional[str]
    topic: Optional[str]
    mlock: Optional[str]
    expirebans_lifetime: int
    reg_time: int
    last_used: int


@dataclass
class Group:
    id: int
    name: str
    description: Optional[str]
    url: Optional[str]
    email: Optional[str]
    flag_private: bool
    reg_time: int


_name_cache: dict[str, dict[int, str]]


def prefetch_names(
    conn: Connection[Row],
) -> None:
    for kind, query in (
        ('account', 'SELECT account.id, nick FROM account, nickname '
            'WHERE account.primary_nick=nickname.id'),
        ('channel', 'SELECT id, channel FROM channel'),
        ('group', 'SELECT id, name FROM "group"'),
    ):
        with conn.cursor(row_factory=tuple_row) as curs:
            _name_cache[kind] = {row[0]: row[1] for row in curs.execute(query)}


def account_name(
    account_id: int,
) -> str:
    return _name_cache['account'][account_id]


def channel_name(
    channel_id: int,
) -> str:
    return _name_cache['channel'][channel_id]


def group_name(
    group_id: int,
) -> str:
    return _name_cache['group'][group_id]


_entity_id = -1


def entity_id(
    ent_id: int,
) -> str:
    return ''.join(chr(ord('A') + ((ent_id // pow(26, i)) % 26))
                   for i in range(8, -1, -1))


def next_entity_id() -> str:
    global _entity_id
    _entity_id += 1
    return entity_id(_entity_id)


def last_entity_id() -> str:
    return entity_id(_entity_id)
