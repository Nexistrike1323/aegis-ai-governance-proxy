package aegis.governance

default allow := false
default action := "BLOCK"
default reason := "Denied by default zero-trust policy"

# Rule 1: Always block if an API secret key is leaked in the prompt
action := "BLOCK" if {
    "SECRET_API_KEY" in input.findings_categories
}
reason := "Prompt contains high-entropy API credential (SECRET_API_KEY)" if {
    "SECRET_API_KEY" in input.findings_categories
}

# Rule 2: Interns cannot access frontier production models or send forbidden keywords
action := "BLOCK" if {
    input.identity.role == "intern"
    input.model == "gpt-4o"
}
reason := "Role 'intern' is restricted from invoking tier-1 model 'gpt-4o'" if {
    input.identity.role == "intern"
    input.model == "gpt-4o"
}

action := "BLOCK" if {
    input.identity.role == "intern"
    count(input.findings_categories) > 0
}
reason := "Role 'intern' is blocked from transmitting sensitive data or forbidden keywords" if {
    input.identity.role == "intern"
    count(input.findings_categories) > 0
}

# Rule 3: Healthcare Doctors can send prompts with PII, but proxy MUST redact before forwarding
allow := true if {
    input.identity.role == "doctor"
    not "SECRET_API_KEY" in input.findings_categories
    count(input.findings_categories) > 0
}
action := "REDACT_AND_ALLOW" if {
    input.identity.role == "doctor"
    not "SECRET_API_KEY" in input.findings_categories
    count(input.findings_categories) > 0
}
reason := "Healthcare role permitted with mandatory inline PII redaction" if {
    input.identity.role == "doctor"
    not "SECRET_API_KEY" in input.findings_categories
    count(input.findings_categories) > 0
}

# Rule 4: Clean prompts from authenticated roles are allowed
allow := true if {
    count(input.findings_categories) == 0
    not (input.identity.role == "intern" && input.model == "gpt-4o")
}
action := "ALLOW" if {
    count(input.findings_categories) == 0
    not (input.identity.role == "intern" && input.model == "gpt-4o")
}
reason := "Clean prompt compliant with tenant policy" if {
    count(input.findings_categories) == 0
    not (input.identity.role == "intern" && input.model == "gpt-4o")
}
