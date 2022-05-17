from sys import stdout
from typing import Union

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import tuple_row


_name_cache: dict[str, dict[int, str]] = {}


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


def db_line(
    *cells: Union[bytes, str, int],
) -> None:
    stdout.buffer.write(b' '.join(
        cell if isinstance(cell, bytes) else str(cell).encode('utf-8')
        for cell in cells
    ))
    stdout.buffer.write(b'\n')
