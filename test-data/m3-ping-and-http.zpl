# Allow a specific adapter to host a service and allow
# another adapter to access it.
# Since we don't yet authenticate users, this policy is expressed using devices.


define adapter as a device with zpr.adapter.cn.
define GoldenClient as an adapter with zpr.adapter.cn:'client.zpr.org'.

define ZServicePingable as a service with device.zpr.adapter.cn:'service.zpr.org'.
define ZWebService as a service with device.zpr.adapter.cn:'service.zpr.org'.

provide ZServicePingable at pingable.svc.zpr over TCP 8080.
allow GoldenClient.
provide ZWebService at web.svc.zpr over TCP 80.
allow GoldenClient.

provide VisaService at visa-admin.svc.zpr over TCP 443.
allow zpr.adapter.cn:'client.zpr.org' devices.
