# TODO: Extend this with link attributes once we have syntax.

define WebServiceGreen as a service with user.bas_id:1234 and service.content:green and device.zpr.adapter.cn:webservice.
define WebServiceBrown as a service with user.bas_id:1234 and service.content:brown and device.zpr.adapter.cn:webservice.
define WebService as a service with user.bas_id:1234 and device.zpr.adapter.cn:webservice.
define FooServiceGreen as a service with user.bas_id:4567 and service.content:green and device.zpr.adapter.cn:fooservice.
define FooServiceBrown as a service with user.bas_id:4567 and service.content:brown and device.zpr.adapter.cn:fooservice.
define FooService as a service with user.bas_id:4567 and device.zpr.adapter.cn:fooservice.

provide WebServiceGreen at web-green.svc.zpr over TCP 80.
allow color:green users.
provide WebServiceBrown at web-brown.svc.zpr over TCP 80.
allow color:brown users.
provide WebService at web.svc.zpr over TCP 80.
allow color:red users.
provide FooServiceGreen at foo-green.svc.zpr over TCP 80.
allow color:green users.
provide FooServiceBrown at foo-brown.svc.zpr over TCP 80.
allow color:brown users.
provide FooService at foo.svc.zpr over TCP 80.
allow color:purple users.
