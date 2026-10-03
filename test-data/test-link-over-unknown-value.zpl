# An "over" clause naming a link attribute that IS configured, but with a value that
# no configured link carries. That is most likely a typo ("use" for "usa"), so the
# compiler warns rather than failing: link values are topology data that a later
# configuration edit may legitimately introduce.

define database as a service with device.zpr.adapter.cn:database.

provide database at database.svc.zpr over TCP 80.
allow redhead users over location:use links.
