# policy/manifest.rego
package guardrails

code_owners = {"admin", "dev-lead"}

protected_kinds = {"ResourceQuota"}

deny[msg] {
  input._user != ""
  input.kind == kind
  kind == protected_kinds[_]
  not input._user == owner
  owner == code_owners[_]
  msg := sprintf("ユーザー '%s' は %s を変更できません", [input._user, input.kind])
}