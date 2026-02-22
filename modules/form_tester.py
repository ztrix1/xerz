import requests
import logging
from urllib.parse import urljoin

# إعداد التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FormTester:
    """
    وحدة اختبار النماذج لاكتشاف الثغرات الأساسية.
    """
    def __init__(self, forms):
        self.forms = forms
        self.results = {
            'xss': [],
            'sql': []
        }

    def test_xss(self, form):
        """اختبار ثغرة XSS بإدخال سكربت بسيط"""
        xss_payload = "<script>alert('XSS')</script>"
        action_url = form['action']
        method = form['method']
        inputs = form['inputs']

        data = {}
        for inp in inputs:
            if inp['type'] in ['text', 'search', 'textarea']:
                data[inp['name']] = xss_payload
            elif inp['type'] == 'submit':
                continue
            else:
                data[inp['name']] = 'test'

        try:
            if method == 'GET':
                response = requests.get(action_url, params=data, timeout=10)
            else:
                response = requests.post(action_url, data=data, timeout=10)

            if xss_payload in response.text:
                logger.warning(f"احتمال XSS في {action_url}")
                self.results['xss'].append({
                    'url': action_url,
                    'method': method,
                    'payload': xss_payload,
                    'inputs': [inp['name'] for inp in inputs if inp['name']]
                })
                return True
        except Exception as e:
            logger.error(f"خطأ في اختبار XSS: {e}")
        return False

    def test_sql(self, form):
        """اختبار ثغرة SQL Injection بإدخال علامة اقتباس بسيطة"""
        sql_payload = "'"
        action_url = form['action']
        method = form['method']
        inputs = form['inputs']

        data = {}
        for inp in inputs:
            if inp['type'] in ['text', 'search', 'textarea', 'hidden']:
                data[inp['name']] = sql_payload
            else:
                data[inp['name']] = 'test'

        try:
            if method == 'GET':
                response = requests.get(action_url, params=data, timeout=10)
            else:
                response = requests.post(action_url, data=data, timeout=10)

            # مؤشرات بسيطة لوجود SQLi: ظهور أخطاء SQL في الصفحة
            sql_errors = [
                "sql", "mysql", "syntax error", "unclosed quotation",
                "you have an error in your sql", "warning: mysql"
            ]
            lower_text = response.text.lower()
            if any(error in lower_text for error in sql_errors):
                logger.warning(f"احتمال SQL Injection في {action_url}")
                self.results['sql'].append({
                    'url': action_url,
                    'method': method,
                    'payload': sql_payload,
                    'inputs': [inp['name'] for inp in inputs if inp['name']]
                })
                return True
        except Exception as e:
            logger.error(f"خطأ في اختبار SQL: {e}")
        return False

    def run_tests(self):
        """تشغيل جميع الاختبارات على النماذج"""
        for i, form in enumerate(self.forms, 1):
            logger.info(f"اختبار النموذج {i}: {form['action']}")
            self.test_xss(form)
            self.test_sql(form)
        return self.results

if __name__ == "__main__":
    # نموذج تجريبي للاختبار
    sample_forms = [
        {
            'action': 'http://testphp.vulnweb.com/search.php',
            'method': 'POST',
            'inputs': [
                {'name': 'searchFor', 'type': 'text'},
                {'name': 'goButton', 'type': 'submit'}
            ]
        }
    ]
    tester = FormTester(sample_forms)
    results = tester.run_tests()
    print("نتائج XSS:", results['xss'])
    print("نتائج SQL:", results['sql'])