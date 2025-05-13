# policy/manifest.rego
package main

import data.deny_kinds

deny contains msg if {
  input.kind in deny_kinds
  msg := sprintf("'%s' は変更禁止リソースのため、変更できません", [input.kind])
}