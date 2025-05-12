# policy/manifest.rego
package main

import data.reviewer
reviewuser := reviewer._user
codeowner := reviewer.owner

deny contains msg if {
  reviewuser != codeowner
  input.kind == "ResourceQuota"
  msg := sprintf("レビュアー '%s' は %s を変更できません", [reviewuser, input.kind])
}