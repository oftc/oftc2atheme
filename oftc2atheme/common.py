from dataclasses import dataclass
from typing import Optional

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import class_row


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


def account_name(
    conn: Connection[Row],
    account_id: int,
) -> str:
    with conn.cursor(row_factory=class_row(Nickname)) as curs:
        result = curs.execute(
            'SELECT nick FROM account, nickname '
            'WHERE account.id = %s AND account.primary_nick=nickname.id',
            (account_id,),
        ).fetchone()
        assert result is not None
        return result.nick


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


def channel_name(
    conn: Connection[Row],
    channel_id: int,
) -> str:
    with conn.cursor(row_factory=class_row(Channel)) as curs:
        result = curs.execute(
            'SELECT channel FROM channel WHERE id = %s', (channel_id,),
        ).fetchone()
        assert result is not None
        return result.channel


@dataclass
class Group:
    id: int
    name: str
    description: Optional[str]
    url: Optional[str]
    email: Optional[str]
    flag_private: bool
    reg_time: int


def group_name(
    conn: Connection[Row],
    group_id: int,
) -> str:
    with conn.cursor(row_factory=class_row(Group)) as curs:
        result = curs.execute(
            'SELECT name FROM group WHERE id = %s', (group_id,),
        ).fetchone()
        assert result is not None
        return result.name


def entity_id(
    ent_id: int,
) -> str:
    return ''.join(chr(ord('A') + ((ent_id // pow(26, i)) % 26))
                   for i in range(8, -1, -1))
