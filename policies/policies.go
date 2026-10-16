// Package policies holds the built-in policy documents shipped with the CLI.
package policies

import (
	_ "embed"

	"fenzi/compiler"
)

//go:embed developer-default.yaml
var developerDefault []byte

// DeveloperDefaultYAML is the built-in org document, for publishing as a starter policy.
func DeveloperDefaultYAML() []byte { return append([]byte(nil), developerDefault...) }

// DeveloperDefault is the base policy on the Free plan.
func DeveloperDefault() *compiler.Document {
	d, err := compiler.Parse(developerDefault)
	if err != nil {
		panic("policies: built-in developer-default does not parse: " + err.Error())
	}
	return d
}
