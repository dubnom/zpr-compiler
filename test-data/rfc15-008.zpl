define Image-database as an device with mach-type:idb.
define server as service with service and device.zpr.adapter.cn:image-database-server.
provide server at image-database-servers.svc.zpr over TCP 443.
allow Image-database.
