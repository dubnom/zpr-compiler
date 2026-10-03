# Requires 'never' support

define internet-gateway as a service with svc-id:9 and device.zpr.adapter.cn:internet-gateway.
provide internet-gateway at internet-gateway.svc.zpr over TCP 443.

never allow internet-gateways.
