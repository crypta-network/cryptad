def planned_names:
  [$planned[] | .name];

def companion_names:
  [
    "stable-1.0-dependency-vulnerability-public-findings.json",
    "stable-1.0-dependency-vulnerability-source-status.json",
    "stable-1.0-dependency-vulnerability-summary.json"
  ];

def allowed_names:
  planned_names
  + if $dependency_vulnerability_active == "true" then companion_names else [] end;

def observed_names:
  [.[].name];

def observed_planned_names:
  [
    observed_names[] as $name
    | select(planned_names | index($name))
    | $name
  ];

def observed_companion_names:
  [
    observed_names[] as $name
    | select(companion_names | index($name))
    | $name
  ];

(planned_names | length) == ($planned | length)
and (planned_names | unique | length) == (planned_names | length)
and (observed_names | unique | length) == (observed_names | length)
and ((observed_names - allowed_names) | length) == 0
and (
  (observed_companion_names | length) == 0
  or (observed_companion_names | sort) == (companion_names | sort)
)
and (
  ($require_complete | not)
  or (
    (observed_planned_names | length) == (planned_names | length)
    and (observed_planned_names | sort) == (planned_names | sort)
  )
)
