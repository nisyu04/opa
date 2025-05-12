# policy/manifest.rego
package guardrails

code_owners = {"admin", "dev-lead"}

protected_kinds = {"ResourceQuota"}

deny[msg] {
  input._user != ""
  input.kind == protected_kinds[_]
  not code_owners[input._user]
  msg := sprintf("ユーザー '%s' は %s を変更できません", [input._user, input.kind])
}