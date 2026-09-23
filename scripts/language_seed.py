# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import re
import unicodedata


# Compact, auditable language packs. Phrases are intentionally high-signal and are
# matched as literal Unicode text after NFKC/case-folding. They are not translated
# dynamically and never leave the host.
LANGUAGE_NAMES = {
    "en": "English", "zh": "Chinese", "ms": "Malay", "ta": "Tamil",
    "id": "Indonesian", "es": "Spanish", "pt": "Portuguese", "fr": "French",
    "de": "German", "hi": "Hindi", "bn": "Bengali", "ur": "Urdu",
    "ar": "Arabic", "ja": "Japanese", "ko": "Korean", "th": "Thai",
    "vi": "Vietnamese", "tl": "Filipino/Tagalog", "ru": "Russian",
}

LEXICONS: dict[str, tuple[str, ...]] = {
    "ms": ("akaun", "kerja", "segera", "pautan", "hadiah", "bayar", "pelaburan", "bungkusan"),
    "id": ("rekening", "investasi", "sekarang", "pekerjaan", "hadiah", "bayar", "paket", "keuntungan", "diblokir", "kirim", "uang"),
    "es": ("cuenta", "empleo", "urgente", "premio", "pagar", "inversión", "contraseña", "paquete"),
    "pt": ("conta", "emprego", "trabalho", "urgente", "prêmio", "pagar", "pague", "investimento", "senha", "encomenda", "meio período"),
    "fr": ("compte", "emploi", "cadeau", "payer", "investissement", "mot de passe", "colis", "immédiatement"),
    "de": ("konto", "arbeit", "dringend", "gewinn", "zahlen", "investition", "passwort", "paket"),
    "vi": ("tài khoản", "việc làm", "khẩn cấp", "trúng thưởng", "thanh toán", "đầu tư", "mật khẩu", "bưu kiện"),
    "tl": ("trabaho", "apurahan", "premyo", "magbayad", "pamumuhunan", "ngayon", "ipadala", "garantisadong"),
}

PHRASES: dict[str, dict[str, tuple[str, ...]]] = {
    "zh": {
        "secret_request": ("发送验证码", "提供密码", "告诉我验证码"), "money_transfer": ("立即转账", "汇款给我", "支付这笔款项"),
        "urgency": ("立即处理", "马上行动", "最后通知"), "delivery_claim": ("包裹投递失败", "快递地址不完整", "支付重新派送费"),
        "job_offer": ("兼职工作", "在家工作", "简单任务赚佣金"), "task_unlock": ("充值解锁任务", "付款解锁提现", "账户出现负余额"),
        "investment": ("投资机会", "加密货币投资", "外汇交易平台"), "guaranteed_return": ("保证收益", "稳赚不赔", "每天固定回报"),
        "prize": ("您中奖了", "领取奖金", "恭喜中奖"), "advance_fee": ("支付手续费", "可退还押金", "缴纳解冻费"),
        "friend_new_number": ("这是我的新号码", "妈妈这是我的新号码", "保存我的新号码"), "tech_support": ("设备已被入侵", "安装远程控制软件", "技术支持部门"),
        "rental_offer": ("出租房先付押金", "看房前支付定金"), "loan_offer": ("保证贷款批准", "放款前支付费用"),
        "recovery_offer": ("追回被骗资金", "支付费用即可退款"),
    },
    "ms": {
        "secret_request": ("hantar otp", "berikan kata laluan", "kongsi kod pengesahan"), "money_transfer": ("pindahkan wang sekarang", "buat bayaran", "hantar wang kepada saya"),
        "urgency": ("bertindak segera", "notis terakhir", "dalam masa satu jam"), "delivery_claim": ("penghantaran bungkusan gagal", "alamat penghantaran tidak lengkap", "bayar yuran penghantaran semula"),
        "job_offer": ("kerja sambilan", "kerja dari rumah", "tugas mudah dapat komisen"), "task_unlock": ("bayar untuk buka tugas", "tambah nilai untuk pengeluaran", "baki negatif"),
        "investment": ("peluang pelaburan", "pelaburan mata wang kripto", "platform dagangan"), "guaranteed_return": ("pulangan dijamin", "keuntungan tanpa risiko", "keuntungan harian"),
        "prize": ("anda telah menang", "tuntut hadiah anda", "pemenang cabutan bertuah"), "advance_fee": ("yuran pemprosesan", "deposit boleh dikembalikan", "yuran pelepasan"),
        "friend_new_number": ("ini nombor baru saya", "ibu ini nombor baru saya", "simpan nombor baru saya"), "tech_support": ("telefon anda telah digodam", "pasang aplikasi ini", "sokongan teknikal"),
        "rental_offer": ("bayar deposit sebelum melihat rumah", "sewa murah bayar dahulu"), "loan_offer": ("pinjaman dijamin lulus", "bayar yuran sebelum pinjaman"),
        "recovery_offer": ("kami boleh dapatkan semula wang anda", "bayar untuk pemulihan dana"),
    },
    "id": {
        "secret_request": ("kirim otp", "berikan kata sandi", "bagikan kode verifikasi"), "money_transfer": ("transfer uang sekarang", "lakukan pembayaran", "kirim uang kepada saya"),
        "urgency": ("bertindak segera", "pemberitahuan terakhir", "dalam satu jam"), "delivery_claim": ("pengiriman paket gagal", "alamat pengiriman tidak lengkap", "bayar biaya pengiriman ulang"),
        "job_offer": ("pekerjaan paruh waktu", "kerja dari rumah", "tugas mudah dapat komisi"), "task_unlock": ("isi saldo untuk membuka tugas", "bayar untuk menarik penghasilan", "saldo negatif"),
        "investment": ("peluang investasi", "investasi kripto", "platform perdagangan"), "guaranteed_return": ("keuntungan dijamin", "tanpa risiko", "keuntungan harian"),
        "prize": ("anda memenangkan hadiah", "klaim hadiah anda", "pemenang undian"), "advance_fee": ("biaya pemrosesan", "deposit dapat dikembalikan", "biaya pencairan"),
        "friend_new_number": ("ini nomor baru saya", "ibu ini nomor baru saya", "simpan nomor baru saya"), "tech_support": ("ponsel anda diretas", "instal aplikasi ini", "dukungan teknis"),
        "rental_offer": ("bayar deposit sebelum melihat rumah", "sewa murah bayar dulu"), "loan_offer": ("pinjaman pasti disetujui", "bayar biaya sebelum pencairan"),
        "recovery_offer": ("kami dapat mengembalikan uang anda", "bayar biaya pemulihan dana"),
    },
    "ta": {
        "secret_request": ("otp ஐ அனுப்பவும்", "கடவுச்சொல்லை வழங்கவும்", "சரிபார்ப்பு குறியீட்டை பகிரவும்"), "money_transfer": ("உடனே பணம் அனுப்பவும்", "பணம் செலுத்தவும்", "எனக்கு பணம் அனுப்புங்கள்"),
        "urgency": ("உடனடியாக செயல்படவும்", "இறுதி அறிவிப்பு", "ஒரு மணி நேரத்திற்குள்"), "delivery_claim": ("பார்சல் விநியோகம் தோல்வி", "முகவரி முழுமையில்லை", "மறுவிநியோக கட்டணம் செலுத்தவும்"),
        "job_offer": ("பகுதி நேர வேலை", "வீட்டிலிருந்து வேலை", "எளிய பணிக்கு கமிஷன்"), "task_unlock": ("பணியை திறக்க பணம் செலுத்தவும்", "பணம் எடுக்க டாப் அப் செய்யவும்", "எதிர்மறை இருப்பு"),
        "investment": ("முதலீட்டு வாய்ப்பு", "கிரிப்டோ முதலீடு", "வர்த்தக தளம்"), "guaranteed_return": ("உத்தரவாத லாபம்", "ஆபத்து இல்லாத வருமானம்", "தினசரி வருமானம்"),
        "prize": ("நீங்கள் பரிசு வென்றுள்ளீர்கள்", "பரிசை பெற்றுக்கொள்ளுங்கள்", "அதிர்ஷ்ட குலுக்கல் வெற்றியாளர்"), "advance_fee": ("செயலாக்க கட்டணம்", "திரும்பப்பெறக்கூடிய வைப்பு", "விடுவிப்பு கட்டணம்"),
        "friend_new_number": ("இது என் புதிய எண்", "அம்மா இது என் புதிய எண்", "என் புதிய எண்ணை சேமிக்கவும்"), "tech_support": ("உங்கள் தொலைபேசி ஹேக் செய்யப்பட்டது", "இந்த செயலியை நிறுவவும்", "தொழில்நுட்ப ஆதரவு"),
        "rental_offer": ("வீட்டை பார்க்கும் முன் வைப்பு செலுத்தவும்",), "loan_offer": ("கடன் நிச்சயம் அங்கீகரிக்கப்படும்",), "recovery_offer": ("உங்கள் பணத்தை மீட்டுத் தரலாம்",),
    },
    "es": {
        "secret_request": ("envía el código otp", "proporciona tu contraseña", "comparte el código de verificación"), "money_transfer": ("transfiere el dinero ahora", "realiza el pago", "envíame dinero"),
        "urgency": ("actúa inmediatamente", "aviso final", "dentro de una hora"), "delivery_claim": ("entrega del paquete fallida", "dirección de entrega incompleta", "paga la tarifa de reenvío"),
        "job_offer": ("trabajo a tiempo parcial", "trabaja desde casa", "tareas sencillas con comisión"), "task_unlock": ("paga para desbloquear la tarea", "deposita para retirar ganancias", "saldo negativo"),
        "investment": ("oportunidad de inversión", "inversión en criptomonedas", "plataforma de trading"), "guaranteed_return": ("ganancias garantizadas", "sin riesgo", "rentabilidad diaria"),
        "prize": ("has ganado un premio", "reclama tu premio", "ganador del sorteo"), "advance_fee": ("tarifa de procesamiento", "depósito reembolsable", "tarifa de liberación"),
        "friend_new_number": ("este es mi nuevo número", "mamá este es mi nuevo número", "guarda mi nuevo número"), "tech_support": ("tu teléfono ha sido hackeado", "instala esta aplicación", "soporte técnico"),
        "rental_offer": ("paga el depósito antes de visitar", "alquiler barato paga primero"), "loan_offer": ("préstamo aprobado garantizado", "paga una tarifa antes del préstamo"), "recovery_offer": ("podemos recuperar tu dinero", "paga para recuperar los fondos"),
    },
    "pt": {
        "secret_request": ("envie o código otp", "forneça sua senha", "compartilhe o código de verificação"), "money_transfer": ("transfira o dinheiro agora", "faça o pagamento", "envie dinheiro para mim"),
        "urgency": ("aja imediatamente", "aviso final", "dentro de uma hora"), "delivery_claim": ("entrega da encomenda falhou", "endereço de entrega incompleto", "pague a taxa de reenvio"),
        "job_offer": ("trabalho de meio período", "trabalhe em casa", "tarefas simples com comissão"), "task_unlock": ("pague para desbloquear a tarefa", "deposite para sacar ganhos", "saldo negativo"),
        "investment": ("oportunidade de investimento", "investimento em criptomoedas", "plataforma de negociação"), "guaranteed_return": ("lucro garantido", "sem risco", "retorno diário"),
        "prize": ("você ganhou um prêmio", "resgate seu prêmio", "vencedor do sorteio"), "advance_fee": ("taxa de processamento", "depósito reembolsável", "taxa de liberação"),
        "friend_new_number": ("este é meu novo número", "mãe este é meu novo número", "salve meu novo número"), "tech_support": ("seu telefone foi invadido", "instale este aplicativo", "suporte técnico"),
        "rental_offer": ("pague o depósito antes da visita",), "loan_offer": ("empréstimo com aprovação garantida",), "recovery_offer": ("podemos recuperar seu dinheiro",),
    },
    "fr": {
        "secret_request": ("envoyez le code otp", "donnez votre mot de passe", "partagez le code de vérification"), "money_transfer": ("transférez l'argent maintenant", "effectuez le paiement", "envoyez-moi de l'argent"),
        "urgency": ("agissez immédiatement", "dernier avertissement", "dans une heure"), "delivery_claim": ("livraison du colis échouée", "adresse de livraison incomplète", "payez les frais de relivraison"),
        "job_offer": ("emploi à temps partiel", "travaillez à domicile", "tâches simples avec commission"), "task_unlock": ("payez pour débloquer la tâche", "déposez pour retirer les gains", "solde négatif"),
        "investment": ("opportunité d'investissement", "investissement en cryptomonnaie", "plateforme de trading"), "guaranteed_return": ("profit garanti", "sans risque", "rendement quotidien"),
        "prize": ("vous avez gagné un prix", "réclamez votre prix", "gagnant du tirage"), "advance_fee": ("frais de traitement", "dépôt remboursable", "frais de déblocage"),
        "friend_new_number": ("voici mon nouveau numéro", "maman voici mon nouveau numéro", "enregistre mon nouveau numéro"), "tech_support": ("votre téléphone a été piraté", "installez cette application", "assistance technique"),
        "rental_offer": ("payez la caution avant la visite",), "loan_offer": ("prêt garanti approuvé",), "recovery_offer": ("nous pouvons récupérer votre argent",),
    },
    "de": {
        "secret_request": ("senden sie den otp-code", "geben sie ihr passwort an", "teilen sie den bestätigungscode"), "money_transfer": ("überweisen sie das geld sofort", "leisten sie die zahlung", "schicken sie mir geld"),
        "urgency": ("handeln sie sofort", "letzte warnung", "innerhalb einer stunde"), "delivery_claim": ("paketzustellung fehlgeschlagen", "lieferadresse unvollständig", "zahlen sie die erneute zustellung"),
        "job_offer": ("teilzeitjob", "arbeiten sie von zu hause", "einfache aufgaben gegen provision"), "task_unlock": ("zahlen sie um die aufgabe freizuschalten", "einzahlen um gewinne abzuheben", "negativer kontostand"),
        "investment": ("investitionsmöglichkeit", "krypto-investition", "handelsplattform"), "guaranteed_return": ("garantierter gewinn", "risikofrei", "tägliche rendite"),
        "prize": ("sie haben einen preis gewonnen", "fordern sie ihren gewinn an", "gewinner der verlosung"), "advance_fee": ("bearbeitungsgebühr", "rückzahlbare kaution", "freigabegebühr"),
        "friend_new_number": ("das ist meine neue nummer", "mama das ist meine neue nummer", "speichere meine neue nummer"), "tech_support": ("ihr telefon wurde gehackt", "installieren sie diese app", "technischer support"),
        "rental_offer": ("kaution vor der besichtigung zahlen",), "loan_offer": ("kredit garantiert genehmigt",), "recovery_offer": ("wir können ihr geld zurückholen",),
    },
    "hi": {
        "secret_request": ("ओटीपी भेजें", "पासवर्ड बताएं", "सत्यापन कोड साझा करें"), "money_transfer": ("अभी पैसे भेजें", "भुगतान करें", "मेरे खाते में पैसे भेजें"),
        "urgency": ("तुरंत कार्रवाई करें", "अंतिम चेतावनी", "एक घंटे के भीतर"), "delivery_claim": ("पार्सल डिलीवरी विफल", "पता अधूरा है", "पुनः डिलीवरी शुल्क भरें"),
        "job_offer": ("पार्ट टाइम नौकरी", "घर से काम", "आसान काम पर कमीशन"), "task_unlock": ("टास्क खोलने के लिए भुगतान करें", "कमाई निकालने के लिए जमा करें", "नकारात्मक बैलेंस"),
        "investment": ("निवेश का अवसर", "क्रिप्टो निवेश", "ट्रेडिंग प्लेटफॉर्म"), "guaranteed_return": ("गारंटीड मुनाफा", "बिना जोखिम", "रोजाना रिटर्न"),
        "prize": ("आपने इनाम जीता है", "अपना पुरस्कार लें", "लकी ड्रॉ विजेता"), "advance_fee": ("प्रोसेसिंग फीस", "वापसी योग्य जमा", "रिलीज शुल्क"),
        "friend_new_number": ("यह मेरा नया नंबर है", "माँ यह मेरा नया नंबर है", "मेरा नया नंबर सेव करें"), "tech_support": ("आपका फोन हैक हो गया है", "यह ऐप इंस्टॉल करें", "तकनीकी सहायता"),
        "rental_offer": ("घर देखने से पहले जमा दें",), "loan_offer": ("गारंटीड लोन मंजूरी",), "recovery_offer": ("हम आपका पैसा वापस दिला सकते हैं",),
    },
    "bn": {
        "secret_request": ("ওটিপি পাঠান", "পাসওয়ার্ড দিন", "যাচাইকরণ কোড শেয়ার করুন"), "money_transfer": ("এখনই টাকা পাঠান", "পেমেন্ট করুন", "আমাকে টাকা পাঠান"),
        "urgency": ("অবিলম্বে ব্যবস্থা নিন", "শেষ সতর্কতা", "এক ঘণ্টার মধ্যে"), "delivery_claim": ("পার্সেল ডেলিভারি ব্যর্থ", "ঠিকানা অসম্পূর্ণ", "পুনরায় ডেলিভারি ফি দিন"),
        "job_offer": ("খণ্ডকালীন চাকরি", "বাড়ি থেকে কাজ", "সহজ কাজে কমিশন"), "task_unlock": ("কাজ খুলতে টাকা দিন", "আয় তুলতে জমা দিন", "নেগেটিভ ব্যালেন্স"),
        "investment": ("বিনিয়োগের সুযোগ", "ক্রিপ্টো বিনিয়োগ", "ট্রেডিং প্ল্যাটফর্ম"), "guaranteed_return": ("নিশ্চিত লাভ", "ঝুঁকিমুক্ত", "দৈনিক রিটার্ন"),
        "prize": ("আপনি পুরস্কার জিতেছেন", "আপনার পুরস্কার দাবি করুন", "লাকি ড্র বিজয়ী"), "advance_fee": ("প্রসেসিং ফি", "ফেরতযোগ্য জমা", "রিলিজ ফি"),
        "friend_new_number": ("এটি আমার নতুন নম্বর", "মা এটি আমার নতুন নম্বর", "আমার নতুন নম্বর সেভ করুন"), "tech_support": ("আপনার ফোন হ্যাক হয়েছে", "এই অ্যাপ ইনস্টল করুন", "প্রযুক্তিগত সহায়তা"),
        "rental_offer": ("বাড়ি দেখার আগে জমা দিন",), "loan_offer": ("ঋণ নিশ্চিত অনুমোদন",), "recovery_offer": ("আমরা আপনার টাকা ফেরত আনতে পারি",),
    },
    "ur": {
        "secret_request": ("او ٹی پی بھیجیں", "پاس ورڈ بتائیں", "تصدیقی کوڈ شیئر کریں"), "money_transfer": ("ابھی رقم بھیجیں", "ادائیگی کریں", "مجھے پیسے بھیجیں"),
        "urgency": ("فوری کارروائی کریں", "آخری انتباہ", "ایک گھنٹے کے اندر"), "delivery_claim": ("پارسل کی ترسیل ناکام", "پتہ نامکمل ہے", "دوبارہ ترسیل کی فیس دیں"),
        "job_offer": ("پارٹ ٹائم نوکری", "گھر سے کام", "آسان کام پر کمیشن"), "task_unlock": ("کام کھولنے کے لیے ادائیگی کریں", "کمائی نکالنے کے لیے جمع کریں", "منفی بیلنس"),
        "investment": ("سرمایہ کاری کا موقع", "کرپٹو سرمایہ کاری", "ٹریڈنگ پلیٹ فارم"), "guaranteed_return": ("یقینی منافع", "بغیر خطرہ", "روزانہ منافع"),
        "prize": ("آپ نے انعام جیتا ہے", "اپنا انعام حاصل کریں", "قرعہ اندازی کے فاتح"), "advance_fee": ("پروسیسنگ فیس", "قابل واپسی جمع", "ریلیز فیس"),
        "friend_new_number": ("یہ میرا نیا نمبر ہے", "امی یہ میرا نیا نمبر ہے", "میرا نیا نمبر محفوظ کریں"), "tech_support": ("آپ کا فون ہیک ہو گیا ہے", "یہ ایپ انسٹال کریں", "تکنیکی مدد"),
        "rental_offer": ("گھر دیکھنے سے پہلے رقم جمع کریں",), "loan_offer": ("قرض کی یقینی منظوری",), "recovery_offer": ("ہم آپ کی رقم واپس لا سکتے ہیں",),
    },
    "ar": {
        "secret_request": ("أرسل رمز التحقق", "أعطني كلمة المرور", "شارك رمز التحقق"), "money_transfer": ("حوّل المال الآن", "قم بالدفع", "أرسل لي المال"),
        "urgency": ("تصرف فوراً", "تحذير أخير", "خلال ساعة"), "delivery_claim": ("فشل تسليم الطرد", "عنوان التسليم غير مكتمل", "ادفع رسوم إعادة التسليم"),
        "job_offer": ("وظيفة بدوام جزئي", "العمل من المنزل", "مهام سهلة مقابل عمولة"), "task_unlock": ("ادفع لفتح المهمة", "أودع لسحب الأرباح", "رصيد سلبي"),
        "investment": ("فرصة استثمار", "استثمار العملات المشفرة", "منصة تداول"), "guaranteed_return": ("ربح مضمون", "بدون مخاطر", "عائد يومي"),
        "prize": ("لقد ربحت جائزة", "استلم جائزتك", "الفائز في السحب"), "advance_fee": ("رسوم المعالجة", "وديعة قابلة للاسترداد", "رسوم الإفراج"),
        "friend_new_number": ("هذا رقمي الجديد", "أمي هذا رقمي الجديد", "احفظ رقمي الجديد"), "tech_support": ("تم اختراق هاتفك", "ثبّت هذا التطبيق", "الدعم الفني"),
        "rental_offer": ("ادفع التأمين قبل المعاينة",), "loan_offer": ("موافقة مضمونة على القرض",), "recovery_offer": ("يمكننا استرداد أموالك",),
    },
    "ja": {
        "secret_request": ("認証コードを送って", "パスワードを教えて", "otpを共有してください"), "money_transfer": ("今すぐ送金してください", "支払いをしてください", "私にお金を送って"),
        "urgency": ("直ちに対応してください", "最終警告", "1時間以内"), "delivery_claim": ("荷物の配達に失敗しました", "住所が不完全です", "再配達料金を支払ってください"),
        "job_offer": ("在宅の副業", "簡単な作業で報酬", "高収入アルバイト"), "task_unlock": ("タスク解除のため入金", "出金するためチャージ", "マイナス残高"),
        "investment": ("投資の機会", "暗号資産投資", "取引プラットフォーム"), "guaranteed_return": ("利益保証", "リスクなし", "毎日の収益"),
        "prize": ("賞品が当選しました", "賞金を受け取る", "抽選の当選者"), "advance_fee": ("手数料を支払う", "返金可能な保証金", "解除手数料"),
        "friend_new_number": ("これが私の新しい番号", "お母さん新しい番号です", "新しい番号を登録して"), "tech_support": ("スマホがハッキングされました", "このアプリをインストール", "テクニカルサポート"),
        "rental_offer": ("内見前に敷金を払って",), "loan_offer": ("ローン審査必ず承認",), "recovery_offer": ("被害金を取り戻せます",),
    },
    "ko": {
        "secret_request": ("인증번호를 보내주세요", "비밀번호를 알려주세요", "otp를 공유하세요"), "money_transfer": ("지금 송금하세요", "결제하세요", "저에게 돈을 보내세요"),
        "urgency": ("즉시 조치하세요", "최종 경고", "한 시간 이내"), "delivery_claim": ("택배 배송에 실패했습니다", "배송 주소가 불완전합니다", "재배송 비용을 결제하세요"),
        "job_offer": ("재택 부업", "간단한 작업으로 수수료", "고수익 아르바이트"), "task_unlock": ("작업 해제를 위해 입금", "출금하려면 충전", "마이너스 잔액"),
        "investment": ("투자 기회", "암호화폐 투자", "거래 플랫폼"), "guaranteed_return": ("수익 보장", "위험 없음", "매일 수익"),
        "prize": ("경품에 당첨되었습니다", "상금을 받으세요", "추첨 당첨자"), "advance_fee": ("처리 수수료", "환불 가능한 보증금", "해제 수수료"),
        "friend_new_number": ("이게 내 새 번호야", "엄마 내 새 번호야", "새 번호를 저장해"), "tech_support": ("휴대폰이 해킹되었습니다", "이 앱을 설치하세요", "기술 지원"),
        "rental_offer": ("집을 보기 전에 보증금을 보내세요",), "loan_offer": ("대출 승인 보장",), "recovery_offer": ("피해금을 되찾아 드립니다",),
    },
    "th": {
        "secret_request": ("ส่งรหัส otp", "บอกรหัสผ่าน", "แชร์รหัสยืนยัน"), "money_transfer": ("โอนเงินตอนนี้", "ชำระเงิน", "ส่งเงินให้ฉัน"),
        "urgency": ("ดำเนินการทันที", "คำเตือนครั้งสุดท้าย", "ภายในหนึ่งชั่วโมง"), "delivery_claim": ("จัดส่งพัสดุไม่สำเร็จ", "ที่อยู่จัดส่งไม่ครบ", "ชำระค่าจัดส่งใหม่"),
        "job_offer": ("งานพาร์ทไทม์", "ทำงานจากที่บ้าน", "งานง่ายได้ค่าคอมมิชชั่น"), "task_unlock": ("จ่ายเงินเพื่อปลดล็อกงาน", "เติมเงินเพื่อถอนรายได้", "ยอดคงเหลือติดลบ"),
        "investment": ("โอกาสการลงทุน", "ลงทุนคริปโต", "แพลตฟอร์มซื้อขาย"), "guaranteed_return": ("รับประกันกำไร", "ไม่มีความเสี่ยง", "ผลตอบแทนรายวัน"),
        "prize": ("คุณได้รับรางวัล", "รับรางวัลของคุณ", "ผู้ชนะการจับรางวัล"), "advance_fee": ("ค่าดำเนินการ", "เงินมัดจำคืนได้", "ค่าปลดล็อก"),
        "friend_new_number": ("นี่คือเบอร์ใหม่ของฉัน", "แม่ นี่เบอร์ใหม่ของฉัน", "บันทึกเบอร์ใหม่ของฉัน"), "tech_support": ("โทรศัพท์ของคุณถูกแฮ็ก", "ติดตั้งแอปนี้", "ฝ่ายสนับสนุนทางเทคนิค"),
        "rental_offer": ("จ่ายมัดจำก่อนดูห้อง",), "loan_offer": ("รับประกันอนุมัติสินเชื่อ",), "recovery_offer": ("เราสามารถกู้เงินของคุณคืนได้",),
    },
    "vi": {
        "secret_request": ("gửi mã otp", "cung cấp mật khẩu", "chia sẻ mã xác minh"), "money_transfer": ("chuyển tiền ngay", "thực hiện thanh toán", "gửi tiền cho tôi"),
        "urgency": ("hành động ngay lập tức", "cảnh báo cuối cùng", "trong vòng một giờ"), "delivery_claim": ("giao bưu kiện thất bại", "địa chỉ giao hàng không đầy đủ", "thanh toán phí giao lại"),
        "job_offer": ("việc làm bán thời gian", "làm việc tại nhà", "nhiệm vụ đơn giản nhận hoa hồng"), "task_unlock": ("trả tiền để mở nhiệm vụ", "nạp tiền để rút thu nhập", "số dư âm"),
        "investment": ("cơ hội đầu tư", "đầu tư tiền điện tử", "nền tảng giao dịch"), "guaranteed_return": ("lợi nhuận đảm bảo", "không rủi ro", "lợi nhuận hàng ngày"),
        "prize": ("bạn đã trúng thưởng", "nhận giải thưởng của bạn", "người thắng xổ số"), "advance_fee": ("phí xử lý", "tiền đặt cọc được hoàn lại", "phí giải ngân"),
        "friend_new_number": ("đây là số mới của tôi", "mẹ ơi đây là số mới của con", "lưu số mới của tôi"), "tech_support": ("điện thoại của bạn đã bị hack", "cài đặt ứng dụng này", "hỗ trợ kỹ thuật"),
        "rental_offer": ("trả cọc trước khi xem nhà",), "loan_offer": ("đảm bảo phê duyệt khoản vay",), "recovery_offer": ("chúng tôi có thể lấy lại tiền cho bạn",),
    },
    "tl": {
        "secret_request": ("ipadala ang otp", "ibigay ang password", "ibahagi ang verification code"), "money_transfer": ("magpadala ng pera ngayon", "magbayad ngayon", "ipadala sa akin ang pera"),
        "urgency": ("kumilos agad", "huling babala", "sa loob ng isang oras"), "delivery_claim": ("nabigo ang paghahatid ng parcel", "kulang ang address", "bayaran ang redelivery fee"),
        "job_offer": ("part time na trabaho", "trabaho mula sa bahay", "simpleng task may komisyon"), "task_unlock": ("magbayad para ma-unlock ang task", "mag top up para makapag-withdraw", "negative balance"),
        "investment": ("oportunidad sa pamumuhunan", "crypto investment", "trading platform"), "guaranteed_return": ("garantisadong kita", "walang panganib", "araw-araw na balik"),
        "prize": ("nanalo ka ng premyo", "kunin ang iyong premyo", "lucky draw winner"), "advance_fee": ("processing fee", "refundable deposit", "release fee"),
        "friend_new_number": ("ito ang bago kong numero", "ma ito ang bago kong numero", "i-save ang bago kong numero"), "tech_support": ("na-hack ang iyong telepono", "i-install ang app na ito", "technical support"),
        "rental_offer": ("magbayad ng deposit bago makita ang bahay",), "loan_offer": ("garantisadong aprubado ang loan",), "recovery_offer": ("mababalik namin ang pera mo",),
    },
    "ru": {
        "secret_request": ("отправьте код подтверждения", "сообщите пароль", "передайте код из смс"), "money_transfer": ("переведите деньги сейчас", "произведите оплату", "отправьте мне деньги"),
        "urgency": ("действуйте немедленно", "последнее предупреждение", "в течение часа"), "delivery_claim": ("доставка посылки не удалась", "адрес доставки неполный", "оплатите повторную доставку"),
        "job_offer": ("работа на дому", "подработка", "простые задания за комиссию"), "task_unlock": ("оплатите чтобы разблокировать задание", "пополните счет для вывода", "отрицательный баланс"),
        "investment": ("инвестиционная возможность", "инвестиции в криптовалюту", "торговая платформа"), "guaranteed_return": ("гарантированная прибыль", "без риска", "ежедневный доход"),
        "prize": ("вы выиграли приз", "получите свой приз", "победитель розыгрыша"), "advance_fee": ("комиссия за обработку", "возвратный депозит", "комиссия за разблокировку"),
        "friend_new_number": ("это мой новый номер", "мама это мой новый номер", "сохрани мой новый номер"), "tech_support": ("ваш телефон взломан", "установите это приложение", "техническая поддержка"),
        "rental_offer": ("внесите залог до просмотра квартиры",), "loan_offer": ("кредит гарантированно одобрен",), "recovery_offer": ("мы вернем ваши потерянные деньги",),
    },
}

NEGATIONS = (
    "do not", "don't", "never", "no comparta", "no envíe", "não envie", "ne partagez pas",
    "nicht senden", "jangan kongsi", "jangan kirim", "不要", "切勿", "அனுப்ப வேண்டாம்",
    "मत भेजें", "পাঠাবেন না", "مت بھیجیں", "لا ترسل", "送らないで", "보내지 마세요",
    "อย่าส่ง", "không gửi", "huwag ipadala", "не отправляйте",
)

AWARENESS = (
    "scam alert", "security awareness", "fraud warning", "amaran penipuan", "peringatan penipuan",
    "alerta de estafa", "aviso de fraude", "alerte arnaque", "betrugswarnung", "诈骗提醒",
    "மோசடி எச்சரிக்கை", "धोखाधड़ी चेतावनी", "প্রতারণা সতর্কতা", "فراڈ سے خبردار",
    "تحذير من الاحتيال", "詐欺注意", "사기 주의", "เตือนภัยมิจฉาชีพ", "cảnh báo lừa đảo",
    "babala sa scam", "предупреждение о мошенничестве",
)


def _script_language(text: str) -> str | None:
    counts = {"zh": 0, "ta": 0, "hi": 0, "bn": 0, "ar": 0, "ja": 0, "ko": 0, "th": 0, "ru": 0}
    urdu_specific = 0
    for char in text:
        cp = ord(char)
        if 0x4E00 <= cp <= 0x9FFF: counts["zh"] += 1
        elif 0x0B80 <= cp <= 0x0BFF: counts["ta"] += 1
        elif 0x0900 <= cp <= 0x097F: counts["hi"] += 1
        elif 0x0980 <= cp <= 0x09FF: counts["bn"] += 1
        elif 0x3040 <= cp <= 0x30FF: counts["ja"] += 2
        elif 0xAC00 <= cp <= 0xD7AF: counts["ko"] += 1
        elif 0x0E00 <= cp <= 0x0E7F: counts["th"] += 1
        elif 0x0400 <= cp <= 0x052F: counts["ru"] += 1
        elif 0x0600 <= cp <= 0x06FF:
            counts["ar"] += 1
            if char in "پچژگٹڈڑںھہےی": urdu_specific += 1
    if counts["ar"] and urdu_specific:
        return "ur"
    language, count = max(counts.items(), key=lambda item: item[1])
    return language if count else None


def detect_language(text: str) -> str:
    script = _script_language(text)
    if script:
        return script
    value = unicodedata.normalize("NFKC", text).casefold()
    def present(token: str) -> bool:
        if " " in token:
            return token in value
        return re.search(rf"(?<!\w){re.escape(token)}(?!\w)", value, re.UNICODE) is not None

    scores = {code: sum(1 for token in tokens if present(token)) for code, tokens in LEXICONS.items()}
    language, score = max(scores.items(), key=lambda item: item[1])
    if score:
        return language
    return "en" if any("a" <= c <= "z" for c in value) else "unknown"


def detect_languages(text: str) -> list[str]:
    """Return plausible language signals for code-switch reporting."""
    primary = detect_language(text)
    languages = [] if primary == "unknown" else [primary]
    value = unicodedata.normalize("NFKC", text).casefold()
    for code, tokens in LEXICONS.items():
        if code in languages:
            continue
        hits = sum(token in value for token in tokens)
        if hits >= 2:
            languages.append(code)
    english_markers = ("your", "account", "please", "payment", "verify", "urgent", "password", "send")
    if "en" not in languages and sum(re.search(rf"(?<!\w){word}(?!\w)", value) is not None for word in english_markers) >= 2:
        languages.append("en")
    return languages[:4] or ["unknown"]


def localized_evidence(text: str, rule_id: str, language: str) -> list[str]:
    value = unicodedata.normalize("NFKC", text).casefold()
    packs = [language] if language in PHRASES else []
    # Mixed-language messages are common. Inspect other packs only when their
    # script or high-signal phrase actually appears.
    packs.extend(code for code in PHRASES if code not in packs)
    hits: list[str] = []
    for code in packs:
        for phrase in PHRASES[code].get(rule_id, ()):
            folded = unicodedata.normalize("NFKC", phrase).casefold()
            start = value.find(folded)
            if start < 0:
                continue
            window = value[max(0, start - 36):start]
            if any(negation in window for negation in NEGATIONS):
                continue
            if phrase not in hits:
                hits.append(phrase)
            if len(hits) == 3:
                return hits
    return hits


def awareness_context(text: str) -> list[str]:
    value = unicodedata.normalize("NFKC", text).casefold()
    return [phrase for phrase in AWARENESS if phrase in value][:3]


def supported_languages() -> list[dict[str, str]]:
    return [{"code": code, "name": name} for code, name in LANGUAGE_NAMES.items()]
