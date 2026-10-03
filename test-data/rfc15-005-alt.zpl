# This had a leading "devices with" class but that is not needed and in fact no longer allowed.
define ClassifiedServices as a service with device.zpr.adapter.cn:classified-services.
provide ClassifiedServices at classified-services.svc.zpr over TCP 443.
allow government, clearance:classified users.
