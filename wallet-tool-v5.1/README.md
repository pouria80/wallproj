# Wallet Scanner — v5.1 (clean build)

پاک‌سازی‌شدهٔ نسخه ۵: فقط فایل‌های اصلی و لازم، بدون پوشه‌های قدیمی،
بدون `__pycache__` و بدون state آزمایشی. یک خط لوله واحد برای اسکن
آفلاین/آنلاین کیف‌پول‌های آلوده به RNG ضعیف.

> ⚠️ این ابزار فقط برای **تحقیق امنیتی و بازیابی کلیدهای خودتان** است.
> موجودی‌سنجی کاملاً READ-ONLY است؛ هیچ تراکنشی ساخته یا امضا نمی‌شود.
> کلید خصوصی هرگز از وب سرویس نمی‌شود (مگر با `--show-secrets` در CLI
> پس از تأیید دستی «YES»).

## ساختار (حداقلِ لازم)

```
wallet-tool-v5.1/
├── app.py                  # رابط وب ادمین → http://127.0.0.1:8777
├── cli.py                  # فرمان‌های scan / status / hits / selftest / fingerprint
├── core/
│   ├── scanner.py          # موتور اسکن: خط لوله واحد RNG × محدودیت × بلوم × بالانس
│   ├── fingerprint.py      # شناسایی خودکار خانواده RNG و کاهش فضای جستجو
│   ├── constraints.py      # حل‌کننده کلمات گمشده BIP-39 + واچ‌لیست/پیشوند/زمان
│   ├── balance.py          # بالانس BTC/LTC/DOGE/ZEC + پیش‌تنظیم آلت‌کوین (dash,bch,eth,trx,xvg)
│   ├── mwc1616.py lcg.py mt19937.py fast_mt.py   # شبیه‌سازهای RNG
│   ├── ecc.py hd.py bip39.py sha256_vec.py       # رمزنگاری و مشتق‌گیری آدرس
│   └── bip39-english.txt                          # واژه‌نامه رسمی ۲۰۴۸ تایی
├── web/                    # داشبورد فارسی RTL (index.html/app.js/style.css)
├── tests/test_v5.py        # تست‌های known-answer (بدون نیاز به pytest)
├── TEST_GUIDE_FA.txt       # آموزش گام‌به‌گام تست در حالت‌های مختلف ★
└── requirements.txt
```

## نصب و اجرا

```bash
pip install -r requirements.txt        # فقط numpy
python cli.py selftest                 # اثبات سراسری خط لوله (بدون اینترنت) ~۱ دقیقه
python app.py 8777                     # وب ادمین روی 127.0.0.1:8777
```

## سه حالت تست سریع (جزئیات کامل در TEST_GUIDE_FA.txt)

```bash
# A) مسیر Randstorm (MWC1616) روی پنجره زمانی، فقط BTC، آفلاین
python cli.py scan --vuln randstorm --mode direct \
  --start 2012-01-01T00:00 --stop 2012-01-01T00:10 --balance offline

# B) کلمه گمشده BIP-39 (حل‌کننده محدودیت، بدون RNG)
python cli.py scan --vuln randstorm --mode bip39 \
  --known-phrase "abandon abandon ... ? ..." --balance offline

# C) انگشت‌نگاری → تنظیم خودکار موتور + جاروب MT19937 با بازه seed صریح
python cli.py fingerprint <hex-sample>
python cli.py scan --vuln mt19937 --mt-seed-lo 0 --mt-seed-hi 100000 \
  --balance offline
```

## تغییرات v5.1 نسبت به v5

- رفع باگ: بالانس ETH دیگر `float(wei)` نمی‌کند (پیش‌تنظیم Blockscout با عدد
  اعشاری؛ مسیر hex Etherscan با مستندات اصلاح شد).
- افزودن جاروب MT19937 با بازه seed صریح (`--mt-seed-lo/hi`) — قبلاً فقط
  پنجره زمانی پشتیبانی می‌شد و عملاً بی‌معنا بود.
- اعتبارسنجی پنجره خالی: `start>=stop` حالا در CLI و API با پیام روشن رد
  می‌شود (قبلاً بی‌صدا هیچ کاری نمی‌کرد).
- حذف فایل‌های زائد نسخه‌های ۲/۳/۴، patch/zip قدیمی، pycache و state.
