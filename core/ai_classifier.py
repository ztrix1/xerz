import json
import os
import numpy as np
import pandas as pd
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityClassifier:
    """
    مصنف ثغرات باستخدام تعلم الآلة.
    يتنبأ باحتمالية وجود ثغرة في نموذج ويب بناءً على خصائصه.
    """
    def __init__(self, model_path='core/vuln_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.vectorizer = None

    def extract_features(self, form):
        """
        استخراج الخصائص من النموذج لتحويلها إلى متجه رقمي.
        """
        features = {}
        # عدد الحقول
        features['num_inputs'] = len(form.get('inputs', []))
        # أنواع الحقول (نصنع خاصية لكل نوع شائع)
        input_types = [inp.get('type', 'text') for inp in form.get('inputs', [])]
        features['has_text'] = 1 if 'text' in input_types else 0
        features['has_password'] = 1 if 'password' in input_types else 0
        features['has_email'] = 1 if 'email' in input_types else 0
        features['has_hidden'] = 1 if 'hidden' in input_types else 0
        features['has_submit'] = 1 if 'submit' in input_types else 0
        features['has_file'] = 1 if 'file' in input_types else 0
        features['has_checkbox'] = 1 if 'checkbox' in input_types else 0
        features['has_radio'] = 1 if 'radio' in input_types else 0
        # طريقة الإرسال
        features['method_post'] = 1 if form.get('method', 'GET').upper() == 'POST' else 0
        # طول الرابط (كخاصية بسيطة)
        features['action_length'] = len(form.get('action', ''))
        # وجود كلمات مفتاحية في الرابط
        action = form.get('action', '').lower()
        features['has_search'] = 1 if 'search' in action else 0
        features['has_login'] = 1 if 'login' in action else 0
        features['has_register'] = 1 if 'register' in action or 'signup' in action else 0
        features['has_comment'] = 1 if 'comment' in action else 0
        features['has_contact'] = 1 if 'contact' in action else 0
        return features

    def prepare_data(self, scan_results_file):
        """
        تحميل نتائج الفحص وتحويلها إلى بيانات تدريب.
        """
        with open(scan_results_file, 'r', encoding='utf-8') as f:
            results = json.load(f)

        # قائمة بالخصائص والتسميات
        X = []
        y = []

        # أولاً: النماذج التي تم اكتشاف ثغرات فيها (إيجابية)
        for vuln in results:
            form = vuln.get('form', {})
            features = self.extract_features(form)
            X.append(features)
            y.append(1)  # 1 تعني وجود ثغرة

        # ثانياً: نحتاج أيضاً إلى نماذج سلبية (بدون ثغرات)
        # في الواقع العملي، يجب أن نحصل عليها من زحف مواقع آمنة.
        # سنقوم بإنشاء بعض النماذج السلبية افتراضياً (يمكن تحسينها لاحقاً)
        # هذا مؤقت للتوضيح.
        negative_forms = [
            {'action': '/', 'method': 'GET', 'inputs': []},
            {'action': '/about', 'method': 'GET', 'inputs': []},
            {'action': '/contact', 'method': 'POST', 'inputs': [{'name': 'name', 'type': 'text'}, {'name': 'email', 'type': 'email'}]},
            {'action': '/search', 'method': 'GET', 'inputs': [{'name': 'q', 'type': 'text'}]},
        ]
        for form in negative_forms:
            features = self.extract_features(form)
            X.append(features)
            y.append(0)

        return X, y

    def train(self, X, y):
        """
        تدريب النموذج.
        """
        # تحويل القواميس إلى متجهات رقمية
        self.vectorizer = DictVectorizer(sparse=False)
        X_vec = self.vectorizer.fit_transform(X)

        # تقسيم البيانات
        X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

        # بناء النموذج
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)

        # تقييم
        y_pred = self.model.predict(X_test)
        logger.info("تقرير التصنيف:\n" + classification_report(y_test, y_pred))

        # حفظ النموذج
        joblib.dump((self.model, self.vectorizer), self.model_path)
        logger.info(f"تم حفظ النموذج في {self.model_path}")

    def load_model(self):
        """تحميل نموذج مدرب مسبقاً."""
        if os.path.exists(self.model_path):
            self.model, self.vectorizer = joblib.load(self.model_path)
            logger.info("تم تحميل النموذج بنجاح")
        else:
            logger.warning("لم يتم العثور على نموذج مدرب. قم بالتدريب أولاً.")

    def predict(self, form):
        """التنبؤ باحتمالية وجود ثغرة في نموذج معين."""
        if self.model is None or self.vectorizer is None:
            self.load_model()
        features = self.extract_features(form)
        features_vec = self.vectorizer.transform([features])
        proba = self.model.predict_proba(features_vec)[0][1]  # احتمال الفئة الإيجابية
        return proba

# مثال استخدام
if __name__ == "__main__":
    classifier = VulnerabilityClassifier()
    # تأكد من وجود ملف النتائج من الفحص السابق
    # قد تحتاج لتعديل اسم الملف حسب ما ظهر لديك
    X, y = classifier.prepare_data('data/scan_results_20260222_014127.json')
    classifier.train(X, y)

    # اختبار على نموذج جديد
    test_form = {
        'action': '/login.php',
        'method': 'POST',
        'inputs': [{'name': 'username', 'type': 'text'}, {'name': 'password', 'type': 'password'}]
    }
    prob = classifier.predict(test_form)
    print(f"احتمال وجود ثغرة في النموذج: {prob:.2f}")