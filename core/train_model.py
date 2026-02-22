import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report
import logging
from core.ai_classifier import VulnerabilityClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_training_data(filepath='data/training_data.json'):
    """تحميل بيانات التدريب من ملف JSON"""
    if not os.path.exists(filepath):
        logger.error(f"ملف البيانات {filepath} غير موجود. قم بتشغيل data_collector.py أولاً.")
        return None, None
    
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    X = []
    y = []
    classifier = VulnerabilityClassifier()  # لاستخدام دالة extract_features
    
    for item in data.get('forms', []):
        features = classifier.extract_features(item['form'])
        X.append(features)
        y.append(1 if item.get('vulnerable', False) else 0)
    
    logger.info(f"تم تحميل {len(X)} عينة.")
    return X, y

def train_and_save(X, y, model_path='core/vuln_model.pkl'):
    """تدريب النموذج وحفظه"""
    vectorizer = DictVectorizer(sparse=False)
    X_vec = vectorizer.fit_transform(X)
    
    # تقييم باستخدام cross-validation
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    scores = cross_val_score(model, X_vec, y, cv=5)
    logger.info(f"دقة cross-validation: {scores.mean():.2f} (+/- {scores.std()*2:.2f})")
    
    # تدريب كامل وتقييم على مجموعة اختبار
    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    logger.info("تقرير التصنيف على مجموعة الاختبار:\n" + classification_report(y_test, y_pred))
    
    # حفظ النموذج والمتجه
    joblib.dump((model, vectorizer), model_path)
    logger.info(f"تم حفظ النموذج في {model_path}")

if __name__ == "__main__":
    X, y = load_training_data('data/training_data.json')
    if X is not None:
        train_and_save(X, y)