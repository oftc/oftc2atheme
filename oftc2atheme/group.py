from dataclasses import dataclass
from enum import Enum

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import class_row

from .common import Group
from .common import account_name
from .common import next_entity_id


@dataclass
class GroupAccess:
    id: int
    group_id: int
    account_id: int
    level: int


# OFTC include/msg.h
class GroupPermission(Enum):
    GRPUSER_FLAG = 0
    GRPIDENTIFIED_FLAG = 1
    GRPMEMBER_FLAG = 2
    GRPMASTER_FLAG = 3


def do_group(
    conn: Connection[Row],
    group: Group,
) -> None:
    flags = '+'
    for flag, flag_char in (
        (not group.flag_private, 'p'),
    ):
        if flag:
            flags += flag_char

    print(f'GRP {next_entity_id()} {group.name} {group.reg_time} {flags}')

    for attr, md_name in (
        (group.description, 'description'),
        (group.url, 'url'),
        (group.email, 'email'),
    ):
        if attr is not None:
            print(f'MDC {group.name} {md_name} {attr}')

    do_group_access(conn, group.name, group.id)


def do_group_access(
    conn: Connection[Row],
    name: str,
    group_id: int,
) -> None:
    acl_flags = {
        GroupPermission.GRPMEMBER_FLAG: '+Acmv',
        GroupPermission.GRPMASTER_FLAG: '+AFbcfimsv',
    }

    with conn.cursor(row_factory=class_row(GroupAccess)) as curs:
        for group_access in curs.execute(
            'SELECT * FROM group_access WHERE group_id = %s', (group_id,),
        ):
            flags = acl_flags[GroupPermission(group_access.level)]
            print(f'GACL {name} {account_name(conn, group_access.account_id)} '
                  f'{flags}')


def do_groups(
    conn: Connection[Row],
) -> None:
    print('GDBV 4')
    print('GFA +AFbcfimsv')
    with conn.cursor(row_factory=class_row(Group)) as curs:
        for group in curs.execute('SELECT * FROM group'):
            do_group(conn, group)
