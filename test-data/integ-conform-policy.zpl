define adapter as a device with zpr.adapter.cn.

# Our node offers PING too
define PingableNode as a service with device.zpr.adapter.cn:'node.zpr.org'.

# Three services, all offered by same adapter
define WebService as a service with device.zpr.adapter.cn:'service.zpr.org'.
define IPerfService as a service with device.zpr.adapter.cn:'service.zpr.org'.
define PingableService as a service with device.zpr.adapter.cn:'service.zpr.org'.

define SpecialClient as an adapter with device.zpr.adapter.cn:'client.zpr.org'.

# the SpecialClient can access three services
service WebService as json {"service_class":"WebService"}.
allow SpecialClient.
service IPerfService as json {"service_class":"IPerfService"}.
allow SpecialClient.
service PingableService as json {"service_class":"PingableService"}.
allow SpecialClient.

# any connected adapter can ping the node
service PingableNode as json {"service_class":"PingableNode"}.
allow adapter.

provide VisaService at visa-admin.svc.zpr over TCP 443.
allow zpr.adapter.cn:'client.zpr.org' devices.
