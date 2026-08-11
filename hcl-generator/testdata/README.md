# Terraform test data

Static inputs used by tests belong under `testdata/`, outside the production
`generated/` tree. Generated production modules always use:

`generated/<provider>/modules/<module>`

Resource names do not determine whether a resource is a test fixture. A test
fixture is identified explicitly by the test that loads it from `testdata/`.
