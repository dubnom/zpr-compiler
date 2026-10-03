define Image-database as a device with mach-type:idb.

define server as service with machine-id and device.zpr.adapter.cn:image-database-server.
provide server at image-database-servers.svc.zpr over TCP 443.

# Rewritten using the 'on' keyword.
allow users on Image-database.

