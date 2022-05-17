"""
Convert an OFTC-ircservices database into an Atheme OpenSEX db for oftc-hybrid.

The following OFTC-ircservices features are lost in conversion:
* The following channel services settings are dropped:
    - AUTOLIMIT
    - AUTOSAVE
    - EXPIREBANS
    - FLOODSERV
    - LEAVEOPS
* The channel description is dropped.
* Entries in channel_akick with a chmode other than 0 are dropped.
* Cloaks which are not enabled are dropped.
* The following account services settings are dropped:
    - SECURE
* The account.flag_email_verified database column is ignored.
* The last_host, last_realname, last_quit_msg fields on an accountare dropped.
* The user's language is ignored and the Atheme default is used.

The following information is invented in the conversion:
* Channel access timestamps are set to the channel last_used time.
* Channel access flags set by access level.
    - MEMBER maps to +Aiv
    - CHANOP maps to +Aiotv
    - MASTER maps to +AFRefiorstv
    - If the channel is AUTOOP, +O is added to CHANOP and MASTER.
    - If the channel is AUTOVOICE, +V is added to MEMBER, CHANOP, and MASTER.
* Group access flags set by access level.
    - MEMBER maps to +Acmv
    - MASTER maps to +AFbcfimsv
* Admin accounts are given the noc service operator class.
* The account's last quit time is used for Atheme's last login time.
"""
from datetime import datetime
from datetime import timezone
from sys import exit

from psycopg import connect

from .channel import do_cf
from .channel import do_channels
from .common import last_entity_id
from .common import prefetch_names
from .group import do_groups
from .user import do_users


def main() -> int:
    print('DBV 12')
    print('MDEP crypto/oftc')
    do_cf()
    print(f'TS {int(datetime.now(tz=timezone.utc).timestamp())}')
    with connect() as conn:
        prefetch_names(conn)
        do_users(conn)
        do_groups(conn)
        do_channels(conn)
    print(f'LUID {last_entity_id()}')
    return 0


exit(main())
