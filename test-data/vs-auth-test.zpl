# Allow a specific adapter to host a service and allow
# another adapter to access it.
# Since we don't yet authenticate users, this policy is expressed using devices.


define adapter as a device with cn.
define GoldenClient as an adapter with cn:'client.zpr.org'.

define ZServicePingable as a service with cn:'service.zpr.org'.
define ZWebService as a service with cn:'service.zpr.org'.

service ZServicePingable as json {"service_class":"ZServicePingable"}.
allow GoldenClient.
service ZWebService as json {"service_class":"ZWebService"}.
allow GoldenClient.

provide VisaService at visa-admin.svc.zpr over TCP 443.
allow zpr.adapter.cn:'client.zpr.org' devices.
