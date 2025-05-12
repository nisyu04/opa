# policy/manifest.rego
package main

import data.allowed_merge_user
import data.deny_kinds
import data.reviewer

deny contains msg if {
  reviewer != allowed_merge_user
  input.kind in deny_kinds
  msg := sprintf("レビュアー '%s' は %s を変更できません", [reviewer, input.kind])
}