import unittest

from client_context import ClientContextError
from client_paths import (
    ClientPathError,
    PROJECT_ROOT,
    build_client_module_path,
    build_client_root,
)


class ClientPathTests(unittest.TestCase):
    def test_expected_roots_and_modules(self) -> None:
        cases = (
            (
                build_client_root("example-client", "dev", "gcp"),
                "runtime/clients/example-client/dev/gcp",
            ),
            (
                build_client_module_path(
                    "example-client", "staging", "gcp", "network"
                ),
                "runtime/clients/example-client/staging/gcp/modules/network",
            ),
            (
                build_client_module_path(
                    "example-client", "prod", "oci", "iam"
                ),
                "runtime/clients/example-client/prod/oci/modules/iam",
            ),
        )
        for path, expected in cases:
            self.assertEqual(path.relative_to(PROJECT_ROOT).as_posix(), expected)

    def test_client_and_environment_isolation(self) -> None:
        paths = {
            build_client_root("client-a", "dev", "gcp"),
            build_client_root("client-b", "dev", "gcp"),
            build_client_root("client-a", "staging", "gcp"),
            build_client_root("client-a", "prod", "gcp"),
        }
        self.assertEqual(len(paths), 4)

    def test_resource_name_is_not_a_path_input(self) -> None:
        expected = build_client_module_path(
            "example-client", "dev", "gcp", "compute"
        )
        for _resource_name in ("vm_test_01", "vm_prod_01", "vm_demo_01"):
            self.assertEqual(
                build_client_module_path(
                    "example-client", "dev", "gcp", "compute"
                ),
                expected,
            )

    def test_traversal_inputs_are_rejected(self) -> None:
        cases = (
            ("../../foo", "dev", "gcp", "compute"),
            ("company/a", "dev", "gcp", "compute"),
            ("company\\a", "dev", "gcp", "compute"),
            ("example-client", "../prod", "gcp", "compute"),
            ("example-client", "dev/../../prod", "gcp", "compute"),
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ClientContextError):
                build_client_module_path(*values)

        for values in (
            ("example-client", "dev", "../../", "compute"),
            ("example-client", "dev", "gcp", "../compute"),
        ):
            with self.subTest(values=values), self.assertRaises(ClientPathError):
                build_client_module_path(*values)


if __name__ == "__main__":
    unittest.main()
