package compute_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func assertTfvarsStringValue(
	t testing.TB,
	content []byte,
	key string,
	want string,
) {
	t.Helper()
	file, diagnostics := hclwrite.ParseConfig(
		content,
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		t.Fatalf("parse terraform.tfvars: %s", diagnostics.Error())
	}
	attribute := file.Body().GetAttribute(key)
	if attribute == nil {
		t.Fatalf("terraform.tfvars is missing %s", key)
	}
	value := strings.TrimSpace(
		string(attribute.Expr().BuildTokens(nil).Bytes()),
	)
	if value != strconv.Quote(want) {
		t.Fatalf("terraform.tfvars %s = %s, want %q", key, value, want)
	}
}

func assertTfvarsKeyCount(
	t testing.TB,
	content string,
	key string,
	want int,
) {
	t.Helper()
	if count := strings.Count(content, key); count != want {
		t.Fatalf("terraform.tfvars %s count = %d, want %d", key, count, want)
	}
}
