# policy/manifest.rego
package main

deny if {
  input._user != "nisyu04"
  input.kind = "ResourceQuota"
  msg := sprintf("レビュアー '%s' は %s を変更できません", [input._user, input.kind])
}