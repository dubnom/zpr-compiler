define ClassifiedServices as a service with device.zpr.adapter.cn:classified-services.
define database as a service with user.bas_id:1234.
define employee as a user with user.bas_id.
define ClassifiedDatabases as a service with device.zpr.adapter.cn:classified-databases.
define AuthService as a service with device.zpr.adapter.cn:'bas.zpr.org'.
define NetAdmins as users with device.zpr.adapter.cn:'admin.zpr.org'.

provide ClassifiedServices at classified-services.svc.zpr over TCP 443.
allow clearance:classified government users.
allow device.zpr.adapter.cn: users.

provide ClassifiedDatabases at classified-databases.svc.zpr over TCP 443.
allow lazy, color:red employees on tint:sales devices.


# FIXME?
# allow classified services to access database.

# ZPL author must define any auth services and ensure that
# the service name is present in the configuration.

// define AuthService as a service with device.zpr.adapter.cn:'bas.zpr.org'
// consider "define AuthService as a service on devices with cn:'bas.zpr.org'

// ZPL author must explicitly grant access to any authentication
// services for adapters.
// Access for the visa service is added by the compiler.

provide AuthService at auth.svc.zpr over TCP 443.
allow zpr.adapter.cn: devices.

# VisaService is a reserved name.
provide VisaService at visa-admin.svc.zpr over TCP 443.
allow hair_color:red NetAdmins.
