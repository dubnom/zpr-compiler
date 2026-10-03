
# Link constraints: the "over" clause (RFC 15).
# Both the allow and the never forms must record their link conditions.

define database as a service with device.zpr.adapter.cn:database.


provide database at database.svc.zpr over TCP 80.
allow redhead users over secure, location:usa links.
never allow baldy users over foreign links.

# A statement with no over clause must record no link conditions.
allow nerd users.

# A VisaService admin statement takes a separate path through the weaver
# (visa_services_to_services, not add_client_policies_allow_or_deny); its
# over clause must be preserved on the admin policy too.
provide VisaService at visa-admin.svc.zpr over TCP 443.
allow redhead users over secure links.
