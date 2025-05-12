# policy/manifest.rego
package main

import data.reviewer
user := reviewer._user
codeowner := "nisyu04"

deny contains msg if {
  user != codeowner
  input.kind == "ResourceQuota"
  msg = "レビュアー '%s' は %s を変更できません"
}