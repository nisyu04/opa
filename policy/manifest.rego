# policy/manifest.rego
package main

code_owners = {"admin"}

protected_kinds = {"ResourceQuota"}

deny if {
  input._user != ""
  protected_kinds[input.kind]
  not code_owners[input._user]
  msg := sprintf("ユーザー '%s' は %s を変更できません", [input._user, input.kind])
}