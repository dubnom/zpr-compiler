
define 'my great service' as a service with device.zpr.adapter.cn:quoted-service.

define mygreatservice as a service with device.zpr.adapter.cn:plain-service.

define ColorRedService as a service with device.zpr.adapter.cn:red-service.

define 'most excellent user' aka 'great ones' as a user with color:red.
provide 'my great service' at quoted.svc.zpr over TCP 80.
allow 'most excellent user'.
provide ColorRedService at red.svc.zpr over TCP 80.
allow 'great ones'.

define mostexcellentuser as a user with color:green.
provide mygreatservice at plain.svc.zpr over TCP 80.
allow mostexcellentuser.

define AuthService as a service with device.zpr.adapter.cn:auth-service.
provide AuthService at auth.svc.zpr over TCP 443.
allow zpr.adapter.cn: devices.

# define NetAdmins as users with device.zpr.adapter.cn:'admin.zpr.org'

# VisaService is a reserved name.
# allow NetAdmins to access VisaService
