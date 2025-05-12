# policy/manifest.rego
package main

import data.reviewer
review_user := reviewer._user
codeowner := reviewer.owner

deny contains msg if {
  review_user != codeowner
  input.kind == "ResourceQuota"
  msg := sprintf("レビュアー '%s' は %s を変更できません", [review_user, input.kind])
}