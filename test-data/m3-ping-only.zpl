# Allow a specific agent to ping another specific agent.
# Since we don't yet authenticate users, this policy is expressed using devices.


define adapter as a device with zpr.adapter.cn.

define ZServicePingable as a service with device.zpr.adapter.cn:'service.zpr.org'.

provide ZServicePingable at pingable.svc.zpr over TCP 8080.
allow zpr.adapter.cn:'client.zpr.org' adapter.

provide VisaService at visa-admin.svc.zpr over TCP 443.
allow zpr.adapter.cn:'client.zpr.org' devices.
