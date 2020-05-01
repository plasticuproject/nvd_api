import unittest
from api.app import app


class BasicTests(unittest.TestCase):
    """Test endpoints and search functions"""


    def setUp(self):
        app.config['DEBUG'] = False
        self.app = app.test_client()
        self.assertEqual(app.debug, False)


    def tearDown(self):
        pass


    def test_schema(self):
        response = self.app.get('/nvd-api/v1/schema', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
    
    
    def test_year(self):
         response = self.app.get('/nvd-api/v1/year/2020?keyword=', follow_redirects=True)
         response2 = self.app.get('/nvd-api/v1/year/bullshit', follow_redirects=True)
         response3 = self.app.get('/nvd-api/v1/year/2000', follow_redirects=True)
         response4 = self.app.get('/nvd-api/v1/year/2020?keyword=the', follow_redirects=True)
         self.assertEqual(response.status_code, 200)
         self.assertEqual(response2.status_code, 404)
         self.assertEqual(response3.status_code, 200)
         self.assertEqual(response4.status_code, 200)


    def test_recent(self):
         response = self.app.get('/nvd-api/v1/recent', follow_redirects=True)
         response2 = self.app.get('/nvd-api/v1/recent?keyword=the', follow_redirects=True)
         response3 = self.app.get('/nvd-api/v1/recent?bullshit=', follow_redirects=True)
         self.assertEqual(response.status_code, 200)
         self.assertEqual(response2.status_code, 200)
         self.assertEqual(response3.status_code, 200)


    def test_modified(self):
         response = self.app.get('/nvd-api/v1/modified', follow_redirects=True)
         response2 = self.app.get('/nvd-api/v1/modified?keyword=the', follow_redirects=True)
         self.assertEqual(response.status_code, 200)
         self.assertEqual(response2.status_code, 200)


    def test_all(self):
         response = self.app.get('/nvd-api/v1/all', follow_redirects=True)
         response2 = self.app.get('/nvd-api/v1/all?keyword=the', follow_redirects=True)
         self.assertEqual(response.status_code, 200)
         self.assertEqual(response2.status_code, 200)


    def test_cve(self):
         response = self.app.get('/nvd-api/v1/CVE-2020-8087', follow_redirects=True)
         response2 = self.app.get('/nvd-api/v1/CVE-2000-1246', follow_redirects=True)
         response3 = self.app.get('/nvd-api/v1/bullshit', follow_redirects=True)
         self.assertEqual(response.status_code, 200)
         self.assertEqual(response2.status_code, 200)
         self.assertEqual(response3.status_code, 404)


if __name__ == "__main__":
    unittest.main()
