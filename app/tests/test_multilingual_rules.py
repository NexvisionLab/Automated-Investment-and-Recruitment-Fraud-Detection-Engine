# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Malay, Indonesian and Tamil scam wordings, and the advance-fee job wording the English rule missed, together with the genuine
messages in the same languages that share words with them ("no registration fee", "past performance is not a guarantee")."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze


def ids(text):
    return {f["id"] for f in analyze(text, online_checks=False)["findings"]}


SCAMS = [
    ("ms_guarantee", "Peluang pelaburan emas! Untung pasti 20% setiap minggu tanpa risiko. Deposit RM1,000 sekarang dan keluarkan RM5,000 dalam sebulan."),
    ("ms_guarantee", "Pelaburan tanpa risiko, modal selamat sepenuhnya. Hubungi kami sekarang."),
    ("ms_guarantee", "Keuntungan dijamin setiap hari, bebas risiko, hanya perlu deposit dahulu."),
    ("ms_unrealistic_return", "Untung pasti 20% setiap minggu, deposit sekarang."),
    ("ms_unrealistic_return", "Dapatkan 5% keuntungan setiap hari dengan robot dagangan kami."),
    ("ms_regulator_claim", "Sudah diluluskan oleh Bank Negara, untung pasti setiap bulan. Hubungi kami di WhatsApp."),
    ("ms_pressure", "Hubungi kami di WhatsApp segera, tempat terhad."),
    ("ms_easy_income", "Lowongan kerja part time dari rumah, gaji Rp500.000 per hari hanya dengan menyukai video."),
    ("ms_fee_job", "Anda terpilih untuk jawatan ini. Sila bayar yuran pendaftaran RM150 hari ini untuk mengesahkan tempat anda."),
    ("ms_fee_job", "Lowongan kerja: untuk memproses lamaran Anda wajib bayar biaya administrasi Rp200.000 lebih dulu."),
    ("ta_fee_job", "வீட்டிலிருந்தே வேலை! தினமும் $150 சம்பாதிக்கலாம், அனுபவம் தேவையில்லை. வேலையை உறுதி செய்ய முதலில் $100 கட்டணம் செலுத்த வேண்டும். இப்போதே WhatsApp மூலம் தொடர்பு கொள்ளுங்கள்."),
    ("ta_easy_income", "வீட்டிலிருந்தே வேலை! தினமும் $150 சம்பாதிக்கலாம்."),
    ("ta_guarantee", "இந்த முதலீட்டில் உறுதியான லாபம் கிடைக்கும், ஆபத்தில்லாத திட்டம்."),
    # English named fee for getting hired
    ("job_upfront_fee", "Congratulations, you have been selected for the Customer Support Officer role. To process your work permit and uniform please pay a refundable fee of $180 by gift card today."),
    ("job_upfront_fee", "You are hired! Please send a $90 visa processing fee to start the job."),
]

GENUINE = [
    "Kami sedang mencari Penolong Akauntan. Gaji RM3,000 hingga RM3,600. Tiada yuran pendaftaran dan tiada bayaran diperlukan untuk memohon. Hantar resume ke hr@firma.com.my.",
    "Lowongan Staf Administrasi di PT Maju Bersama, gaji Rp5.000.000 per bulan. Tidak ada biaya pendaftaran atau biaya apa pun dalam proses rekrutmen. Kirim CV ke rekrutmen@majubersama.co.id.",
    "Laporan bulanan: reksa dana campuran kami memberikan imbal hasil 1,2% bulan ini. Kinerja masa lalu bukan jaminan hasil di masa depan dan Anda dapat kehilangan modal. Produk ini terdaftar dan diawasi OJK; baca prospektus sebelum berinvestasi.",
    "Buletin bulanan: dana seimbang kami mencatatkan pulangan 1.2% pada September. Prestasi lalu bukan jaminan pulangan masa depan dan anda mungkin rugi. Sila baca prospektus di laman web kami untuk maklumat risiko dan yuran.",
    "Jualan hujung tahun! Diskaun sehingga 50% untuk semua produk minggu ini sahaja. Stok terhad. Lawati kedai kami di Jalan Ampang.",
    "Promo akhir tahun! Diskon hingga 30% setiap hari untuk semua produk. Tempat terbatas untuk workshop gratis kami hari Sabtu.",
    "நாங்கள் ஒரு கணக்காளரை வேலைக்கு தேடுகிறோம். சம்பளம் $3,000 முதல் $3,500 வரை. தகுதி: டிப்ளோமா மற்றும் ஒரு வருட அனுபவம். விண்ணப்பங்களை hr@abc.com.sg முகவரிக்கு அனுப்பவும். எந்த கட்டணமும் இல்லை.",
    "உங்கள் மின்சாரக் கட்டணம் $85.40 செலுத்த வேண்டிய கடைசி தேதி 20 செப்டம்பர். உங்கள் செயலியில் செலுத்தலாம்.",
    "We are hiring a warehouse assistant. There is no registration fee and no processing fee. We never charge candidates any fee. Apply at careers@acme.com.sg.",
    "Our company will pay for your work permit and visa processing fee. Relocation support is included for successful candidates.",
    "Benefits include medical insurance, and the company pays the insurance fee for all staff after probation.",
    "Your registration fee for the course is due today; pay through the student portal by 5pm.",
]


class MultilingualRuleTests(unittest.TestCase):
    def test_each_scam_wording_matches_its_rule(self):
        for rule, text in SCAMS:
            with self.subTest(rule=rule, text=text[:40]):
                self.assertIn(rule, ids(text))

    def test_genuine_messages_in_the_same_languages_raise_nothing(self):
        for text in GENUINE:
            with self.subTest(text=text[:40]):
                result = analyze(text, online_checks=False)
                self.assertEqual([f["id"] for f in result["findings"]], [])
                self.assertEqual(result["risk_band"], "Low")

    def test_a_malay_investment_scam_is_no_longer_low(self):
        text = "Peluang pelaburan emas! Untung pasti 20% setiap minggu tanpa risiko. Deposit RM1,000 sekarang dan keluarkan RM5,000 dalam sebulan. Sudah diluluskan oleh Bank Negara. Hubungi kami di WhatsApp segera, tempat terhad."
        self.assertIn(analyze(text, online_checks=False)["risk_band"], {"High", "Critical"})

    def test_a_tamil_fee_scam_is_no_longer_low(self):
        text = SCAMS[10][1]
        self.assertIn(analyze(text, online_checks=False)["risk_band"], {"Elevated", "High", "Critical"})

    def test_an_english_named_fee_scam_is_high(self):
        self.assertIn(analyze(SCAMS[13][1], online_checks=False)["risk_band"], {"High", "Critical"})

    def test_a_no_fee_promise_does_not_hide_a_fee_demand_in_the_same_message(self):
        text = "There is no interview fee. But to secure the job you must pay a $150 registration fee first, by gift card."
        self.assertIn("job_upfront_fee", ids(text))


if __name__ == "__main__":
    unittest.main()
