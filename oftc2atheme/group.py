from dataclasses import dataclass
from enum import Enum
from typing import Optional

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import class_row

from .common import account_name
from .common import db_line
from .common import group_name
from .common import next_entity_id


@dataclass
class Group:
    id: int
    name: bytes
    description: Optional[bytes]
    url: Optional[bytes]
    email: Optional[bytes]
    flag_private: bool
    reg_time: int


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
    # Fixes the prefix
    name = group_name(group.id)

    flags = '+'
    for flag, flag_char in (
        (not group.flag_private, 'p'),
    ):
        if flag:
            flags += flag_char

    db_line('GRP', next_entity_id(), name, group.reg_time, flags)

    for attr, md_name in (
        (group.description, 'description'),
        (group.url, 'url'),
        (group.email, 'email'),
    ):
        if attr is not None:
            db_line('MDC', name, md_name, attr)


def do_group_access(
    conn: Connection[Row],
) -> None:
    acl_flags = {
        GroupPermission.GRPMEMBER_FLAG: '+Acmv',
        GroupPermission.GRPMASTER_FLAG: '+AFbcfimsv',
    }

    with conn.cursor(row_factory=class_row(GroupAccess)) as curs:
        for group_access in curs.execute('SELECT * FROM group_access'):
            name = group_name(group_access.group_id)
            flags = acl_flags[GroupPermission(group_access.level)]
            db_line('GACL', name, account_name(group_access.account_id), flags)


def do_groups(
    conn: Connection[Row],
) -> None:
    db_line('GDBV', '4')
    db_line('GFA', '+AFbcfimsv')
    with conn.cursor(row_factory=class_row(Group)) as curs:
        for group in curs.execute('SELECT * FROM "group"'):
            do_group(conn, group)
    do_group_access(conn)
