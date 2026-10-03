# Fixture for the bin2 determinism test (see tests/zpl-test.rs).
# All following access rules are scoped to the provided database service.
# The `never` statement stays ahead of the `allow` statements in source order.

define employee as a user with user.bas_id.
define database as a service with device.zpr.adapter.cn:database and user.bas_id:1234.

provide database at database.svc.zpr over TCP 80.
never allow color:red employees.
allow lazy, color:green employees on tint:sales devices.
allow clearance:classified government users.

define AuthService as a service with device.zpr.adapter.cn:'bas.zpr.org'.
provide AuthService at auth.svc.zpr over TCP 443.
allow zpr.adapter.cn: devices.

define NetAdmins as users with device.zpr.adapter.cn:'admin.zpr.org'.
provide VisaService at visa-admin.svc.zpr over TCP 443.
allow hair_color:red NetAdmins.
