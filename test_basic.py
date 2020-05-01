import os
import unittest

from api.app import app

class BasicTests(unittest.TestCase):


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
         response = self.app.get('/nvd-api/v1/year/2020', follow_redirects=True)
         self.assertEqual(response.status_code, 200)


    def test_recent(self):
         response = self.app.get('/nvd-api/v1/recent', follow_redirects=True)
         self.assertEqual(response.status_code, 200)


    def test_modified(self):
         response = self.app.get('/nvd-api/v1/modified', follow_redirects=True)
         self.assertEqual(response.status_code, 200)


    def test_all(self):
         response = self.app.get('/nvd-api/v1/all', follow_redirects=True)
         self.assertEqual(response.status_code, 200)


    def test_cve(self):
         response = self.app.get('/nvd-api/v1/CVE-2010-4662', follow_redirects=True)
         self.assertEqual(response.status_code, 200)


    def test_search(self):
         response = self.app.get('/nvd-api/v1/year/2019?keyword=sudo', follow_redirects=True)
         self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
