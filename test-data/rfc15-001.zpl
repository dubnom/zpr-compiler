define laptop AKA laptops as device with optional tag managed.
define ClassifiedDatabase as service with device.zpr.adapter.cn:classified-database.
provide ClassifiedDatabase at classified-database.svc.zpr over TCP 443.

# Re-written using the 'on' keyword
allow cleared government users on managed laptops.

