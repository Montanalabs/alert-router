#! VULNERABLE alert-router — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant page

let raw = fetch<web>
privileged { page(raw) }  # tainted -> tool: REJECTED
