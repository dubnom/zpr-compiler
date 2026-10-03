define database as a service with device.zpr.adapter.cn:database.
define employee as a user with user.bas_id.
define signalService as a service.

provide database at database.svc.zpr over TCP 80.

# No ON
allow color:red employees
and signal "red employee" to signalService.

allow employees and signal "employee" to signalService.

allow color:red employees and signal "red tint access" to signalService.

allow employees on hardened devices and signal "accessed" to signalService.
