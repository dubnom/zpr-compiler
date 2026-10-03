define ClassifiedServices as a service with device.zpr.adapter.cn:classified-services.
provide ClassifiedServices at classified-services.svc.zpr over TCP 443.
allow clearance:classified government users.
