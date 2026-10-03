define WebService as a service with user.markers:{web, service} and service.content:{green, marketing, edu, govt, red} and device.zpr.adapter.cn:webservice.

provide WebService at web.svc.zpr over TCP 80.
allow role:{manager, marketing} users.

allow role:intern users.

# Ok to use set notation here too though not required.
allow role:{foo} users.
