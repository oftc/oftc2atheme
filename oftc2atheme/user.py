from base64 import b16decode
from base64 import b64encode
from dataclasses import dataclass

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import class_row

from .common import Account
from .common import Nickname
from .common import account_name
from .common import channel_name
from .common import next_entity_id


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
    name = account_name(conn, account.id)

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
            name = account_name(conn, autojoin.account_id)
            joined = ','.join(channel_name(conn, channel_id)
                              for channel_id in autojoin.channel_ids)
            print(f'MDU {name} private:autojoin {joined}')


def do_account_access(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(AccountAccess)) as curs:
        for access in curs.execute('SELECT * FROM account_access'):
            name = account_name(conn, access.account_id)
            print(f'AC {name} {access.entry}')


def do_nickname(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(Nickname)) as curs:
        for nick in curs.execute('SELECT * FROM nickname'):
            name = account_name(conn, nick.account_id)
            print(f'MN {name} {nick.nick} {nick.reg_time} {nick.last_seen}')


def do_account_fingerprint(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(AccountFingerprint)) as curs:
        for cfp in curs.execute('SELECT * FROM account_fingerprint'):
            name = account_name(conn, cfp.account_id)
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
