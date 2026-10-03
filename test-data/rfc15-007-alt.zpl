define Image-database as a service with svc-id and device.zpr.adapter.cn:image-database.
provide Image-database at image-database.svc.zpr over TCP 443.

# Removed the leading "devices with" as that is no longer allowed.
allow cleared government users.

