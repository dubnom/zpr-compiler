# Removed leading "endpints with"
define ClassifiedDatabase as service with device.zpr.adapter.cn:classified-database.
provide ClassifiedDatabase at classified-database.svc.zpr over TCP 443.
allow cleared government users.
