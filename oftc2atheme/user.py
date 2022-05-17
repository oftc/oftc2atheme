from base64 import b16decode
from base64 import b64encode
from dataclasses import dataclass
from typing import Optional

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import class_row

from .common import account_name
from .common import channel_name
from .common import next_entity_id


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
class AccountAccess:
    id: int
    account_id: int
    entry: str


@dataclass
class AccountFingerprint:
    id: int
    account_id: int
    fingerprint: str
    nickname_id: int


@dataclass
class AccountAutojoinQ:
    account_id: int
    channel_ids: list[int]


def do_user(
    conn: Connection[Row],
    account: Account,
) -> None:
    name = account_name(account.id)

    if account.password.startswith('xxx'):
        crypt = f'$oftc${"x"*16}$xxx'
    else:
        hashed = b64encode(b16decode(account.password, casefold=True))
        crypt = f'$oftc${account.salt}${hashed.decode("utf-8")}'

    flags = '+'
    for flag, flag_char in (
        (account.flag_private, 'ps'),  # private implies hidemail
        (not account.flag_verified, 'W'),
    ):
        if flag:
            flags += flag_char

    print(f'MU {next_entity_id()} {name} {crypt} {account.email} '
          f'{account.reg_time} {account.last_quit_time} {flags} default')

    for attr, md_name in (
        (account.url, 'url'),
        (
            account.cloak if account.flag_cloak_enabled else None,
            'private:usercloak',
        ),
        ('1' if account.flag_enforce else None, 'private:doenforce'),
    ):
        if attr is not None:
            print(f'MDU {name} {md_name} {attr}')

    if account.flag_admin:
        print(f'SO {name} noc +')


def do_account_autojoin(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(AccountAutojoinQ)) as curs:
        for autojoin in curs.execute(
            'SELECT account_id, array_agg(channel_id) AS channel_ids '
            'FROM account_autojoin GROUP BY account_id',
        ):
            name = account_name(autojoin.account_id)
            joined = ','.join(channel_name(channel_id)
                              for channel_id in autojoin.channel_ids)
            print(f'MDU {name} private:autojoin {joined}')


def do_account_access(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(AccountAccess)) as curs:
        for access in curs.execute('SELECT * FROM account_access'):
            name = account_name(access.account_id)
            print(f'AC {name} {access.entry}')


def do_nickname(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(Nickname)) as curs:
        for nick in curs.execute('SELECT * FROM nickname'):
            name = account_name(nick.account_id)
            print(f'MN {name} {nick.nick} {nick.reg_time} {nick.last_seen}')


def do_account_fingerprint(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(AccountFingerprint)) as curs:
        for cfp in curs.execute('SELECT * FROM account_fingerprint'):
            name = account_name(cfp.account_id)
            print(f'MCFP {name} {cfp.fingerprint}')


def do_users(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(Account)) as curs:
        for account in curs.execute('SELECT * FROM account'):
            do_user(conn, account)
    do_account_autojoin(conn)
    do_account_access(conn)
    do_nickname(conn)
    do_account_fingerprint(conn)
