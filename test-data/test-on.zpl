

define Image-database as a service with service.level:classified and device.zpr.adapter.cn:image-database.
define ClassifiedImageDatabase as a service with service.level:classified and device.zpr.adapter.cn:classified-image-database.
define EncryptedImageDatabase as a service with service.level:classified and device.zpr.adapter.cn:encrypted-image-database.
define SecretImageDatabase as a service with service.level:secret and device.zpr.adapter.cn:secret-image-database.
define ServiceRequiresEncrypted as an Image-database with tag device.encrypted.
define LockedDevice as an device with tag encrypted.
define AuthService as a service with device.zpr.adapter.cn:auth-service.
define NetAdmins as users with device.zpr.adapter.cn:'admin.zpr.org'.

# ON remains available on the client side; service selection comes from each
# provide declaration, and service/device attributes live on that service class.
provide Image-database at image-database.svc.zpr over TCP 443.
allow clearance:classified government users on hardened devices.
provide ClassifiedImageDatabase at classified-image-database.svc.zpr over TCP 443.
allow clearance:classified government users.
provide EncryptedImageDatabase at encrypted-image-database.svc.zpr over TCP 443.
allow clearance:classified government users.
provide SecretImageDatabase at secret-image-database.svc.zpr over TCP 443.
allow clearance:classified government users.
provide ServiceRequiresEncrypted at encrypted-service.svc.zpr over TCP 443.
allow clearance:public users.
provide AuthService at auth.svc.zpr over TCP 443.
allow zpr.adapter.cn: devices.
provide VisaService at visa-admin.svc.zpr over TCP 443.
allow NetAdmins.
