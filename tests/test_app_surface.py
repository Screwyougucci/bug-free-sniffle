import unittest

from darthscanner.app_surface import inspect_app_surface


class AppSurfaceInventoryTests(unittest.TestCase):
    def test_collects_forms_and_control_metadata_without_values(self):
        html = """
        <form method="post" action="/account/save?session=secret" enctype="multipart/form-data">
          <input type="email" name="email" id="email" required autocomplete="email" value="private@example.test">
          <input type="password" name="password" value="super-secret">
          <button type="submit" name="submit">Save</button>
        </form>
        """
        result = inspect_app_surface("https://example.test/profile", html)
        self.assertEqual(result["form_count"], 1)
        form = result["forms"][0]
        self.assertEqual(form["method"], "POST")
        self.assertEqual(form["action"], "https://example.test/account/save")
        self.assertTrue(form["same_origin_action"])
        self.assertEqual([c["name"] for c in form["controls"]], ["email", "password", "submit"])
        self.assertTrue(form["controls"][0]["required"])
        self.assertNotIn("private@example.test", str(result))
        self.assertNotIn("super-secret", str(result))
        self.assertNotIn("session=secret", str(result))

    def test_marks_external_action_without_following_it(self):
        result = inspect_app_surface(
            "https://example.test/login",
            '<form action="https://outside.test/collect?token=secret"><input name="q"></form>',
        )
        form = result["forms"][0]
        self.assertEqual(form["action"], "https://outside.test/collect")
        self.assertFalse(form["same_origin_action"])
        self.assertNotIn("token=secret", str(result))

    def test_detects_framework_hints(self):
        html = '<div id="__next"></div><script id="__NEXT_DATA__"></script><div data-reactroot></div>'
        result = inspect_app_surface("https://example.test/", html)
        self.assertIn("Next.js", result["framework_hints"])
        self.assertIn("React", result["framework_hints"])

    def test_counts_controls_outside_forms(self):
        result = inspect_app_surface(
            "https://example.test/",
            '<input name="search"><form><textarea name="message"></textarea></form>',
        )
        self.assertEqual(result["controls_outside_forms"], 1)
        self.assertEqual(result["forms"][0]["controls"][0]["tag"], "textarea")

    def test_rejects_non_http_page_url(self):
        with self.assertRaises(ValueError):
            inspect_app_surface("file:///tmp/page.html", "<form></form>")


if __name__ == "__main__":
    unittest.main()
