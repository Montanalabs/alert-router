#! Alert router — untrusted an alert can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires page — the alert router sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant page

type Team = Sre | Backend | Data
type Decision = Page(Team) | Ack

let raw = fetch<web>  # UNTRUSTED an alert — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { page(d) }  # act on the trusted decision only
