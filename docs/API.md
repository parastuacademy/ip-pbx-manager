# مستندات REST API — نسخه ۱ (v1)

REST API پنل تلفن آی‌پی به نرم‌افزارهای دیگر اجازه می‌دهد به سانترال وصل شوند: برقراری تماس از داخل CRM، خواندن گزارش تماس‌ها، دانلود ضبط مکالمه و دریافت خودکار رخدادها با وب‌هوک.

- **آدرس پایه:** `http://<آدرس-پنل>:8080/api/v1`
- **قالب پاسخ:** همه پاسخ‌ها JSON با پوشش ثابت:
  - موفق: `{"ok": true, "data": ...}` (گاهی همراه `"meta"`)
  - خطا: `{"ok": false, "error": {"code": "...", "message": "..."}}`
- **بدنه درخواست‌ها:** JSON (`Content-Type: application/json`) — فرم هم پذیرفته می‌شود.
- **مشخصات OpenAPI** برای ایمپورت در Postman/Insomnia: فایل `docs/openapi.yaml`

---

## ۱) احراز هویت

هر درخواست (به‌جز `ping`) باید کلید API را همراه داشته باشد، با یکی از دو هدر:

```
Authorization: Bearer pbx_0123456789abcdef0123456789abcdef
X-API-Key: pbx_0123456789abcdef0123456789abcdef
```

کلیدها را مدیر از پنل می‌سازد: **منوی «اتصال‌ها (API)»**. هر کلید:
- فقط یک‌بار هنگام ساخت به‌صورت کامل نمایش داده می‌شود (در دیتابیس هش‌شده ذخیره می‌شود)؛
- قابل باطل‌کردن فوری است؛
- می‌تواند به IP یا شبکه خاص محدود شود (مثلاً `192.168.1.10, 10.0.0.0/24`)؛
- سقف مصرف آن **۱۲۰ درخواست در هر دقیقه** است — درخواست بیشتر با `429` و هدر `Retry-After` رد می‌شود.

## ۲) Endpointها

| روش | مسیر | توضیح |
|---|---|---|
| GET | `/api/v1/ping` | بررسی سلامت و نسخه — بدون کلید |
| POST | `/api/v1/calls/click-to-call` | کلیک‌به‌تماس: اول گوشی کارمند زنگ می‌خورد، بعد مقصد |
| GET | `/api/v1/calls` | گزارش تماس‌ها با فیلتر و صفحه‌بندی |
| GET | `/api/v1/calls/{uniqueid}` | جزئیات یک تماس |
| GET | `/api/v1/calls/{uniqueid}/recording` | دانلود فایل ضبط تماس |
| GET | `/api/v1/extensions` | فهرست داخلی‌ها + وضعیت آنلاین بودن |
| GET | `/api/v1/trunk` | وضعیت ثبت ترانک (وصل/قطع) |
| GET | `/api/v1/webhooks` | فهرست وب‌هوک‌های ثبت‌شده |
| POST | `/api/v1/webhooks` | ثبت وب‌هوک جدید |
| DELETE | `/api/v1/webhooks/{id}` | حذف وب‌هوک |
| POST | `/api/v1/webhooks/{id}/test` | ارسال رویداد آزمایشی |

> جستجوی تماس‌ها روی **آخرین ۵۰۰۰ تماس** انجام می‌شود (برای سازمان‌های کوچک و متوسط بیش از کافی است).

---

### ۲.۱) ping

```bash
curl -s http://192.168.1.10:8080/api/v1/ping
```

```json
{"ok": true, "data": {"service": "ip-pbx-manager", "api": "v1", "version": "2.1"}}
```

### ۲.۲) کلیک‌به‌تماس (click-to-call)

**مفهوم:** سیستم اول داخلیِ کارمند (`agent`) را زنگ می‌زند؛ وقتی گوشی را برداشت، به مقصد (`destination`) وصل می‌کند. مقصد می‌تواند داخلیِ داخل سازمان یا شماره بیرونی باشد. تماس‌های برقرارشده از این مسیر در CDR با `userfield=api` علامت می‌خورند.

پارامترها:

| فیلد | لازم | توضیح |
|---|---|---|
| `agent` | بله | شماره داخلی کارمندی که تماس می‌گیرد — باید موجود باشد |
| `destination` | بله | داخلی موجود، یا شماره بیرونی ۳ تا ۲۰ رقم (مثل `02112345678` یا `09121234567` — بدون `+`) |
| `timeout` | خیر | چند ثانیه برای برداشتن گوشیِ کارمند صبر شود (۵ تا ۱۲۰، پیش‌فرض ۴۵) |

```bash
curl -s http://192.168.1.10:8080/api/v1/calls/click-to-call \
  -H "Authorization: Bearer pbx_0123..." \
  -H "Content-Type: application/json" \
  -d '{"agent": "101", "destination": "02188776655", "timeout": 30}'
```

پاسخ `202` (درخواست پذیرفته شد و تماس در حال برقراری است):

```json
{"ok": true, "data": {"agent": "101", "destination": "02188776655",
                      "context": "outbound", "timeout": 30}}
```

خطاهای رایج: `422 unknown_extension` (کارمند وجود ندارد)، `422 invalid_destination` (مقصد نامعتبر)، `503 asterisk_unreachable` (هسته تماس در دسترس نیست).

### ۲.۳) گزارش تماس‌ها

پارامترهای کوئری:

| پارامتر | توضیح |
|---|---|
| `q` | جستجوی عدد در شماره مبدأ یا مقصد |
| `date` | فقط یک روز — قالب `YYYY-MM-DD` |
| `disposition` | یکی از `ANSWERED`, `NO ANSWER`, `BUSY`, `FAILED`, `CONGESTION` |
| `limit` | حداکثر تعداد رکورد (۱ تا ۱۰۰۰، پیش‌فرض ۱۰۰) |
| `offset` | برای صفحه‌بندی |

```bash
curl -s "http://192.168.1.10:8080/api/v1/calls?disposition=NO%20ANSWER&limit=50" \
  -H "Authorization: Bearer pbx_0123..."
```

```json
{"ok": true,
 "data": [{"uniqueid": "1762499200.2", "src": "02188776655",
           "dst": "02144001122", "start": "2026-11-07 11:00:00",
           "answer": "", "end": "2026-11-07 11:00:20",
           "duration": "20", "billsec": "0",
           "disposition": "NO ANSWER", "userfield": "inbound",
           "direction": "inbound"}],
 "meta": {"total": 1, "limit": 50, "offset": 0,
          "note": "search covers the last 5000 calls"}}
```

میدان `direction`: `inbound` (ورودی) / `outbound` (خروجی) / `internal` (درون‌سازمانی) / `unknown`.

### ۲.۴) ضبط مکالمه

```bash
curl -s -o call.wav "http://192.168.1.10:8080/api/v1/calls/1762498800.1/recording" \
  -H "Authorization: Bearer pbx_0123..."
```

اگر ضبطی وجود نداشته باشد: `404 no_recording` (ضبط مکالمه باید برای داخلیِ مربوط فعال شده باشد).

### ۲.۵) داخلی‌ها و ترانک

```bash
curl -s http://192.168.1.10:8080/api/v1/extensions -H "Authorization: Bearer pbx_0123..."
```

```json
{"ok": true, "data": [{"ext": "101", "display_name": "پذیرش",
                       "record": true, "voicemail": false, "online": true}],
 "meta": {"ami_online": true, "online": ["101"]}}
```

اگر هسته تماس در دسترس نباشد `online` برابر `null` و `meta.ami_online` برابر `false` می‌شود.

---

## ۳) وب‌هوک‌ها

وب‌هوک یعنی: به‌محض پایان هر تماس، پنل اطلاعات تماس را به آدرس نرم‌افزار شما **POST** می‌کند. برای «پاپ‌آپ پرونده مشتری»، «کارتابل پیگیری تماس‌های از دست‌رفته» و ثبت خودکار تماس‌ها در CRM استفاده می‌شود.

**رخدادهای موجود:**

| رخداد | زمان ارسال |
|---|---|
| `call.ended` | پایان هر تماس (هر وضعیتی) |
| `call.answered` | تماسی که پاسخ داده شد |
| `call.missed` | تماسی که پاسخ داده نشد (مشغول / بی‌پاسخ / ناموفق) |
| `webhook.test` | فقط برای تست اتصال |

> رخدادها بر پایه CDR است — یعنی پس از پایان تماس ارسال می‌شوند و قابل‌اعتمادند. اعلانِ «همین الان زنگ می‌خورد» (لحظه‌ی زنگ) در نقشه راه نسخه‌های بعدی است.

**ثبت وب‌هوک** (از پنل یا از خود API):

```bash
curl -s http://192.168.1.10:8080/api/v1/webhooks \
  -H "Authorization: Bearer pbx_0123..." -H "Content-Type: application/json" \
  -d '{"url": "https://crm.example.com/hooks/pbx", "events": ["call.missed", "call.ended"]}'
```

پاسخ `201` — **`secret` فقط همین یک‌بار کامل برگردانده می‌شود؛ ذخیره‌اش کنید.**

### بدنه‌ای که دریافت می‌کنید

```json
{
  "event": "call.missed",
  "occurred_at": "2026-11-07 11:00:20",
  "data": {
    "uniqueid": "1762499200.2",
    "direction": "inbound",
    "src": "02188776655",
    "dst": "101",
    "start": "2026-11-07 11:00:00",
    "answer": "",
    "end": "2026-11-07 11:00:20",
    "duration": "20",
    "billsec": "0",
    "disposition": "NO ANSWER"
  }
}
```

### هدرهای ارسالی

| هدر | توضیح |
|---|---|
| `Content-Type: application/json` | — |
| `X-PBX-Event` | نام رخداد (مثل `call.missed`) |
| `X-PBX-Delivery-Id` | شناسه یکتای همین ارسال |
| `X-PBX-Signature` | `sha256=<HMAC-SHA256 کل بدنه با secret>` — برای اطمینان از اینکه درخواست واقعاً از پنل آمده |

### اعتبارسنجی امضا در سمت شما

**Python:**

```python
import hmac, hashlib

def verify(secret: str, body: bytes, signature_header: str) -> bool:
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + expected, signature_header)
```

**PHP:**

```php
$expected = 'sha256=' . hash_hmac('sha256', $body, $secret);
hash_equals($expected, $_SERVER['HTTP_X_PB_SIGNATURE'] ?? '');
```

**قواعد تحویل:** پاسخ `2xx` تا ۸ ثانیه = تحویل موفق. در غیر این صورت تا ۴ تلاش با فاصله ۱۵ ثانیه، ۱ دقیقه و ۵ دقیقه تکرار می‌شود و آخرین وضعیت در پنل («آخرین وضعیت» هر وب‌هوک) دیده می‌شود. برای آزمایش: از پنل دکمه «ارسال آزمایشی» یا از API مسیر `POST /api/v1/webhooks/{id}/test`.

---

## ۴) کدهای خطا

| HTTP | code | معنی |
|---|---|---|
| 401 | `missing_key` | کلید همراه درخواست نیست |
| 401 | `invalid_key` | کلید ناشناخته یا باطل‌شده |
| 403 | `ip_not_allowed` | کلید فقط برای IP دیگری مجاز است |
| 404 | `not_found` / `no_recording` | تماس یا وب‌هوک یا ضبط پیدا نشد |
| 422 | `invalid_input` | فیلدها نامعتبرند (جزئیات در `message`) |
| 429 | `rate_limited` | از سقف ۱۲۰ درخواست در دقیقه گذشتید |
| 503 | `asterisk_unreachable` | هسته تماس (Asterisk) در دسترس نیست |

## ۵) مثال کامل در پایتون

```python
import requests

BASE = "http://192.168.1.10:8080/api/v1"
KEY = "pbx_0123456789abcdef0123456789abcdef"
H = {"Authorization": f"Bearer {KEY}"}

# کلیک‌به‌تماس از داخل CRM
r = requests.post(f"{BASE}/calls/click-to-call", headers=H,
                  json={"agent": "101", "destination": "09121234567"})
print(r.json())

# ۵۰ تماس بی‌پاسخ آخر
r = requests.get(f"{BASE}/calls", headers=H,
                 params={"disposition": "NO ANSWER", "limit": 50})
for call in r.json()["data"]:
    print(call["src"], call["start"], call["disposition"])
```

## ۶) نکات امنیتی

- کلید API فقط در بک‌اندِ نرم‌افزار مقصد ذخیره شود؛ هرگز در کد فرانت‌اند/مرورگر قرار نگیرد (این API برای فراخوانی از سرور طراحی شده و هدر CORS عمومی ندارد).
- برای هر نرم‌افزار یک کلید جدا بسازید تا در صورت لو رفتن، فقط همان یک مورد باطل شود.
- اگر نرم‌افزار مقصد روی شبکه داخلی است، کلید را با `ip_allow` به همان IP قفل کنید.
- پنل و API را برای دسترسی از اینترنت فقط از طریق HTTPS عمومی کنید (مثلاً با reverse-proxy).
