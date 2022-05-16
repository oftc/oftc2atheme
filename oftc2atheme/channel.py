from dataclasses import dataclass
from enum import Enum
from typing import Literal
from typing import Optional

from psycopg import Connection
from psycopg.rows import Row
from psycopg.rows import class_row

from .common import Channel
from .common import account_name
from .common import group_name


@dataclass
class ChannelAccess:
    id: int
    channel_id: int
    account_id: Optional[int]
    group_id: Optional[int]
    level: int


@dataclass
class ChannelAkick:
    id: int
    channel_id: int
    setter: Optional[int]
    target: Optional[int]
    mask: Optional[str]
    reason: str
    time: int
    duration: int
    chmode: int


# OFTC include/msg.h
class ChannelPermission(Enum):
    CHUSER_FLAG = 0
    CHIDENTIFIED_FLAG = 1
    MEMBER_FLAG = 2
    CHANOP_FLAG = 3
    MASTER_FLAG = 4


# https://oftc.net/ChannelModes/
# Atheme include/atheme/channels.h & include/atheme/protocol/oftc-hybrid.h
MODE_LIST = {
    'c': 0x00001000,  # CMODE_NOCOLOR (oftc-hybrid)
    'i': 0x00000001,  # CMODE_INVITE
    'm': 0x00000008,  # CMODE_MOD
    'n': 0x00000010,  # CMODE_NOEXT
    'p': 0x00000040,  # CMODE_PRIV
    's': 0x00000080,  # CMODE_SEC
    't': 0x00000100,  # CMODE_TOPIC
    'z': 0x00004000,  # CMODE_OPMOD (oftc-hybrid)
    'M': 0x00200000,  # CMODE_MODREG (oftc-hybrid)
    'R': 0x00002000,  # CMODE_REGONLY (oftc-hybrid)
    'S': 0x00400000,  # CMODE_SSLONLY (oftc-hybrid)
    'l': 0x00000004,  # CMODE_LIMIT
    'k': 0x00000002,  # CMODE_KEY
}


def do_cf() -> None:
    print('CF +AFORVbefiorstv')


def parse_mlock(
    mlock: Optional[str],
) -> tuple[int, int, int, str]:
    flags = [0, 0]
    limit = 0
    key = ''

    if mlock is None:
        return flags[0], flags[1], limit, key

    args = mlock.split(' ')
    argi = 1

    dir: Literal[0, 1]
    if mlock[0] not in ('+', '-'):
        raise ValueError(f'malformed mlock: {mlock}')

    for char in mlock:
        if char == '+':
            i = 0
        elif char == '-':
            i = 1
        elif char == 'k':
            if i == 0:
                key = args[argi]
                argi += 1
                flags[1] &= ~MODE_LIST['k']
            else:
                key = ''
                flags[1] |= MODE_LIST['k']

        elif char == 'l':
            if i == 0:
                limit = int(args[argi])
                argi += 1
                flags[1] &= ~MODE_LIST['l']
            else:
                limit = 0
                flags[1] |= MODE_LIST['l']

        else:
            if char not in MODE_LIST:
                raise ValueError(f'Unknown mode {char} in mlock')
            flag = MODE_LIST[char]
            if flag is not None:
                flags[i] |= flag
                flags[(i + 1) % 2] &= ~flag

    if argi != len(args):
        raise RuntimeError(
            f'Had {len(args)} mlock args but only parsed {argi}',
        )

    return flags[0], flags[1], limit, key


def do_channel(
    conn: Connection[Row],
    channel: Channel,
) -> None:
    flags = '+'
    for flag, flag_char in (
        (channel.flag_private, 'p'),
        (channel.flag_restricted, 'r'),
        (channel.flag_topic_lock, 't'),
        (channel.flag_verbose, 'v'),
    ):
        if flag:
            flags += flag_char

    mlock_on, mlock_off, mlock_limit, mlock_key = (
        parse_mlock(channel.mlock))

    print(f'MC {channel.channel} {channel.reg_time} {channel.last_used} '
          f'{flags} {mlock_on} {mlock_off} {mlock_limit} {mlock_key}')

    for attr, md_name in (
        (channel.url, 'url'),
        (channel.email, 'email'),
        (channel.entrymsg, 'private:entrymsg'),
        (channel.topic, 'private:topic:text'),
        (channel.reg_time, 'private:channelts'),
    ):
        if attr is not None:
            print(f'MDC {channel.channel} {md_name} {attr}')

    do_channel_access(conn, channel)
    do_channel_akick(conn, channel)


def do_channel_access(
    conn: Connection[Row],
    channel: Channel,
) -> None:
    acl_flags = {
        ChannelPermission.MEMBER_FLAG: '+Aiv',
        ChannelPermission.CHANOP_FLAG: '+Aiotv',
        ChannelPermission.MASTER_FLAG: '+AFRefiorstv',
    }
    if channel.flag_autoop:
        for level in (
            ChannelPermission.CHANOP_FLAG,
            ChannelPermission.MASTER_FLAG,
        ):
            acl_flags[level] += 'O'
    if channel.flag_autovoice:
        for level in (
            ChannelPermission.MEMBER_FLAG,
            ChannelPermission.CHANOP_FLAG,
            ChannelPermission.MASTER_FLAG,
        ):
            acl_flags[level] += 'V'

    with conn.cursor(row_factory=class_row(ChannelAccess)) as curs:
        for channel_access in curs.execute(
            'SELECT * FROM channel_access WHERE channel_id = %s',
            (channel.id,),
        ):
            if channel_access.account_id is not None:
                target = account_name(conn, channel_access.account_id)
            elif channel_access.group_id is not None:
                target = f'!{group_name(conn, channel_access.group_id)}'
            else:
                raise ValueError('channel_access with no target')

            flags = acl_flags[ChannelPermission(channel_access.level)]

            print(
                f'CA {channel.channel} {target} {flags} {channel.last_used} *',
            )


def do_channel_akick(
    conn: Connection[Row],
    channel: Channel,
) -> None:
    with conn.cursor(row_factory=class_row(ChannelAkick)) as curs:
        # chmode 0 is AKICK_MASK cf. OFTC include/servicemask.h
        for akick in curs.execute(
            'SELECT * FROM channel_akick '
            'WHERE channel_id = %s AND chmode = 0', (channel.id,),
        ):
            if akick.setter is not None:
                setter = account_name(conn, akick.setter)
            else:
                setter = '*'

            if akick.target is not None:
                target = account_name(conn, akick.target)
            elif akick.mask is not None:
                target = akick.mask
            else:
                raise ValueError('Invalid ChannelAkick')

            print(f'CA {channel.channel} {target} +b {akick.time} {setter}')
            print(f'MDA {channel.channel} {target} reason {akick.reason}')
            if akick.duration > 0:
                expires = akick.time + akick.duration
                print(f'MDA {channel.channel} {target} expires {expires}')


def do_channels(
    conn: Connection[Row],
) -> None:
    with conn.cursor(row_factory=class_row(Channel)) as curs:
        for channel in curs.execute('SELECT * FROM channel'):
            do_channel(conn, channel)