

نظرة عامة

أداة DEX Dumper هي أداة مبرمجة بلغة Python مصممة لاستخراج ملفات DEX من التطبيقات قيد التشغيل مباشرة من الذاكرة. تعمل على أجهزة الأندرويد التي تمتلك صلاحية الروت (Root) من خلال Termux دون الحاجة إلى إطار عمل Frida أو أدوات خارجية أخرى.

المميزات

· استخراج باستخدام الروت: الوصول المباشر للذاكرة عبر /proc/pid/mem
· مسح مناطق الذاكرة: يفحص خرائط ذاكرة العمليات للعثور على ملفات DEX
· دعم رؤوس متعددة: يدعم إصداري رأس DEX 035 و 037
· قائمة تفاعلية: واجهة سطر أوامر سهلة الاستخدام
· تفريغ انتقائي: يسمح باختيار مناطق ذاكرة محددة للمسح
· تتبع التقدم: يظهر تقدم العمل في الوقت الفعلي أثناء تفريغ الذاكرة

المتطلبات

· جهاز أندرويد موقوع (يمتلك صلاحية الروت)
· تطبيق Termux
· Python 3.x مثبت في Termux
· صلاحية الروت (su) ممنوحة لـ Termux

التثبيت

1. قم بتثبيت Termux من F-Droid أو متجر Play
2. افتح Termux وقم بتنفيذ الأوامر التالية:

```bash
pkg update && pkg upgrade
pkg install python
pkg install git
git clone https://github.com/Hasanxpx/dex_dumper.py.git
cd dex-dumper
```

1. امنح صلاحية الروت لـ Termux:

```bash
su
```

طريقة الاستخدام

1. شغل السكربط بصلاحية الروت:

```bash
python dex_dumper.py
```

1. اتبع القائمة التفاعلية:
   · حدد اسم الباكيج المستهدف (مثل com.example.app)
   · اختر مناطق الذاكرة للمسح (اختياري)
   · اختر طريقة الاستخراج (رأس 035 أو 037)
   · ابدأ عملية الاستخراج

هيكل الملفات

```
/sdcard/dumpDex/
└── [اسم الباكيج]/
    ├── classes.dex
    ├── classes2.dex
    └── ...
```

نصائح استعمال مع Mt Manager

1. عرض الملفات المستخرجة: استخدم Mt Manager للتنقل إلى مجلد /sdcard/dumpDex لعرض الملفات المستخرجة
2. تحليل الملفات: Mt Manager يسمح لك بفحص وتعديل ملفات DEX مباشرة
3. مقارنة الملفات: استخدم خاصية المقارنة في Mt Manager لمقارنة الملفات المستخرجة مع الملفات الأصلية
4. إعادة التوقيع: بعد التعديل، استخدم Mt Manager لإعادة توقيع التطبيق

ملاحظات مهمة

· ⚠️ هذه الأداة تتطلب جهازًا موقوعًا (Rooted)
· ⚠️ بعض التطبيقات قد تستخدم تقنيات حماية ضد استخراج الملفات
· ⚠️ الاستخدام مسؤولية المستخدم فقط

الدعم والمشاكل

إذا واجهتك أي مشاكل:

1. تأكد من أن الجهاز موقوع بشكل صحيح
2. تأكد من منح Termux صلاحية الروت
3. تأكد من أن التطبيق المستهدف يعمل عند التنفيذ

---

English Version

Overview

DEX Dumper is a Python tool designed for extracting DEX files from running Android applications directly from memory. It works on rooted Android devices through Termux without requiring Frida or other external frameworks.

Features

· Root-based Extraction: Uses direct memory access via /proc/pid/mem
· Memory Region Scanning: Scans through process memory maps to find DEX files
· Multiple Header Support: Supports both DEX header versions 035 and 037
· Interactive Menu: User-friendly command-line interface
· Selective Dumping: Allows choosing specific memory regions to scan
· Progress Tracking: Shows real-time progress during memory dumping

Requirements

· Rooted Android device
· Termux application
· Python 3.x installed in Termux
· Root access (su) granted to Termux

Installation

1. Install Termux from F-Droid or Play Store
2. Open Termux and run:

```bash
pkg update && pkg upgrade
pkg install python
pkg install git
git clone https://github.com/Hasanxpx/dex_dumper.py.git
cd dex-dumper
```

1. Grant root access to Termux:

```bash
su
```

Usage

1. Run the script with root privileges:

```bash
python dex_dumper.py
```

1. Follow the interactive menu:
   · Set target package name (e.g., com.example.app)
   · Select memory regions to scan (optional)
   · Choose extraction method (Header 035 or 037)
   · Start extraction process

File Structure

```
/sdcard/dumpDex/
└── [package-name]/
    ├── classes.dex
    ├── classes2.dex
    └── ...
```

Mt Manager Usage Tips

1. View extracted files: Use Mt Manager to navigate to /sdcard/dumpDex folder
2. Analyze files: Mt Manager allows you to inspect and modify DEX files directly
3. Compare files: Use Mt Manager's compare feature to analyze differences
4. Re-signing: After modification, use Mt Manager to re-sign the APK

Important Notes

· ⚠️ This tool requires a rooted device
· ⚠️ Some applications may use protection against dumping
· ⚠️ Use at your own responsibility

Support and Issues

If you encounter any problems:

1. Ensure proper root access
2. Verify Termux has been granted root permissions
3. Make sure the target application is running during execution
