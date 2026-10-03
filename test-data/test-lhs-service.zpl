
define MyDb as a service with tag blue and device.zpr.adapter.cn:mydb.
define MyWeb as a service with tag red.

provide MyDb at mydb.svc.zpr over TCP 80.
Allow red services.
Allow green users on yellow devices.
Allow red services on yellow devices.
Allow user.green, brown services on yellow devices.
Allow service.brown, green users on yellow devices.
Allow MyWeb.



# If you put a service class on the LHS, implies actor must provide a service.
# AND match the attribute.
