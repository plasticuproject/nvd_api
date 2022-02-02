"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2022  plasticuproject@pm.me
"""
import unittest
from api.app import app


class ApiTests(unittest.TestCase):
    """Test endpoints and search functions."""

    def setUp(self) -> None:
        app.config["DEBUG"] = False
        self.app = app.test_client()
        self.assertEqual(app.debug, False)

    def tearDown(self) -> None:
        pass

    def test_schema(self) -> None:
        """Test schema endpoint."""
        response = self.app.get("/nvd-api/v1/schema", follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_year(self) -> None:
        """Test year endpoint."""
        response = self.app.get("/nvd-api/v1/year/2020?keyword=",
                                follow_redirects=True)
        response2 = self.app.get("/nvd-api/v1/year/bullshit",
                                 follow_redirects=True)
        response3 = self.app.get("/nvd-api/v1/year/2000",
                                 follow_redirects=True)
        response4 = self.app.get("/nvd-api/v1/year/2020?keyword=the",
                                 follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response2.status_code, 404)
        self.assertEqual(response3.status_code, 200)
        self.assertEqual(response4.status_code, 200)

    def test_recent(self) -> None:
        """Test recent endpoint."""
        response = self.app.get("/nvd-api/v1/recent", follow_redirects=True)
        response2 = self.app.get("/nvd-api/v1/recent?keyword=the",
                                 follow_redirects=True)
        response3 = self.app.get("/nvd-api/v1/recent?bullshit=",
                                 follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response3.status_code, 200)

    def test_modified(self) -> None:
        """Test modified endpoint."""
        response = self.app.get("/nvd-api/v1/modified", follow_redirects=True)
        response2 = self.app.get("/nvd-api/v1/modified?keyword=the",
                                 follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response2.status_code, 200)

    def test_all(self) -> None:
        """Test all endpoint."""
        response = self.app.get("/nvd-api/v1/all", follow_redirects=True)
        response2 = self.app.get("/nvd-api/v1/all?keyword=the",
                                 follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response2.status_code, 200)

    def test_cve(self) -> None:
        """Test cve endpoint."""
        response = self.app.get("/nvd-api/v1/CVE-2020-8087",
                                follow_redirects=True)
        response2 = self.app.get("/nvd-api/v1/CVE-2000-1246",
                                 follow_redirects=True)
        response3 = self.app.get("/nvd-api/v1/bullshit", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response3.status_code, 404)

    def test_cpe(self) -> None:
        """Test cpe endpoint."""
        response = self.app.get("/nvd-api/v1/cpe/23/arris",
                                follow_redirects=True)
        response2 = self.app.get(
            "/nvd-api/v1/cpe/23/arris?keyword=buffer overflow",
            follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response2.status_code, 200)


if __name__ == "__main__":
    unittest.main()
