# policy/manifest.rego
package main

code_owners = {"nisyu04"}

protected_kinds = {"ResourceQuota"}

deny if {
  input._user != "nisyu04"
  input.kind == protected_kinds[_]
  msg := sprintf("レビュアー '%s' は %s を変更できません", [input._user, input.kind])
}