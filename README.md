# Real-Time-Threat-Detection - Gelişmiş Siber Güvenlik İzleme Sistemi

Python'un güçlü kütüphanelerini kullanarak gelişmiş bir siber güvenlik izleme sistemi nasıl oluşturulur? Bu makalede, makine öğrenmesi destekli bir güvenlik sisteminin detaylı implementasyonunu inceleyeceğiz.

## Sistemin Genel Yapısı

Güvenlik izleme sistemimiz şu ana bileşenlerden oluşuyor:

1. Log Analizi
2. Anomali Tespiti (Makine Öğrenmesi)
3. Tehdit İstihbaratı
4. Uyarı Sistemi
5. Otomatik Engelleme Mekanizması

## Gerekli Kütüphaneler

```python
import re
import json
import smtplib
import requests
import joblib
import numpy as np
from email.mime.text import MIMEText
from collections import defaultdict
from sklearn.ensemble import IsolationForest
```

## Log Analizi ve Tehdit Tespiti

Sistem, üç farklı log dosyasını sürekli olarak izliyor:
- auth.log: Kimlik doğrulama logları
- nginx/access.log: Web sunucu erişim logları
- firewall.log: Güvenlik duvarı logları

```python
LOG_FILES = ["/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/firewall.log"]
```

Log analizi şu tehditleri tespit ediyor:
1. Brute Force saldırıları (5 başarısız giriş denemesi)
2. Bilinen zararlı IP'lerden gelen istekler
3. Anormal davranış kalıpları

## Makine Öğrenmesi ile Anomali Tespiti

Sistem, Isolation Forest algoritmasını kullanarak normal olmayan davranışları tespit ediyor:

```python
def train_anomaly_model():
    data = np.random.rand(100, 3)
    model = IsolationForest(contamination=0.05)
    model.fit(data)
    joblib.dump(model, "anomaly_model.pkl")
```

Bu model şu özellikleri analiz ediyor:
- Log satırı uzunluğu
- Sayısal karakter sayısı
- Alfabetik karakter sayısı

## Uyarı Sistemi

Tehdit tespit edildiğinde sistem iki farklı kanaldan uyarı gönderiyor:

1. Email Uyarıları:
```python
def send_email_alert(subject, message):
    msg = MIMEText(message)
    msg["Subject"] = subject
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.login(username, password)
    server.sendmail(sender, recipient, msg.as_string())
```

2. Slack Bildirimleri:
```python
def send_slack_alert(message):
    payload = {"text": message}
    requests.post(SLACK_WEBHOOK_URL, json=payload)
```

## Otomatik Koruma Mekanizmaları

Sistem, tehdit tespit ettiğinde otomatik olarak harekete geçiyor:
- Brute force saldırısı yapan IP'leri otomatik engelleme
- Zararlı IP'leri güvenlik duvarında bloklama
- Tehdit istihbaratı verilerini sürekli güncelleme

## Nasıl Kullanılır?

1. Gerekli kütüphaneleri yükleyin:
```bash
pip install scikit-learn numpy requests joblib
```

2. Konfigürasyon ayarlarını güncelleyin:
- Email sunucu bilgileri
- Slack webhook URL'i
- Güvenlik duvarı API endpoint'i
- Log dosyası konumları

3. Sistemi çalıştırın:
```bash
python security_monitor.py
```

## Sonuç

Bu sistem, modern siber tehditlere karşı otomatik ve akıllı bir koruma sağlıyor. Makine öğrenmesi sayesinde bilinmeyen tehditleri bile tespit edebiliyor ve güvenlik ekibini anında bilgilendiriyor.

Sistemin güçlü yanları:
- Gerçek zamanlı tehdit tespiti
- Otomatik koruma mekanizmaları
- Çoklu bildirim kanalları
- Makine öğrenmesi destekli anomali tespiti

Gelecek geliştirmeler için öneriler:
- Derin öğrenme modellerinin eklenmesi
- Daha fazla log kaynağının entegrasyonu
- Tehdit istihbaratı kaynaklarının çeşitlendirilmesi
- Web arayüzü eklenmesi

Bu projeyi [GitHub'dan indirebilir ve kendi ihtiyaçlarınıza göre özelleştirebilirsiniz.](https://ondernet.net/post/python-ile-gelismis-siber-guvenlik-izleme-sistemi)
