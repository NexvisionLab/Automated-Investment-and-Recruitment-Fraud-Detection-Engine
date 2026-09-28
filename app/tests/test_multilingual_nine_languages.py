# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Spanish, French, Portuguese, German, Vietnamese, Tagalog, Hindi, Arabic and Thai job and investment scams, and the genuine messages
in those languages that share their words ("nunca pedimos dinero", "aucun frais", "kostenlos", "không bao giờ yêu cầu").

The engine caught 1 of 45 scams in these languages before `rules_multilingual.py`. `data/multilingual_cases.json` holds 396 synthetic
messages (198 scam, 198 genuine) written by separate models that were shown no rule, in four sets. Each set was scored ONCE, untouched,
before its failures were used to improve the rules, so every set here is now tuned and none measures coverage any more:
  dev       read while writing the rules
  holdout   first run  20/45 scams caught,  5/45 genuine flagged   (deployed engine: 3/45)
  fresh     first run  34/54 scams caught,  2/54 genuine flagged   (deployed engine: 6/54)
  fresh2    first run  15/54 scams caught,  3/54 genuine flagged   (deployed engine: 4/54); 14/31 in the job and investment classes
All four are kept as regression cases. KNOWN_MISSES are the scams still not caught: 21 belong to classes this engine does not cover
(bank "safe account", customs fee on a gift, refund and bank phishing), several are Arabic or Thai typed in Latin letters, and the
rest are variants worth a later rule. Fixing one should shrink the set, never grow it."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze
from normalization import fold_for_matching

FLAGGED = 25  # the "Elevated" band starts here
CASES = json.loads((Path(__file__).parent / "data" / "multilingual_cases.json").read_text(encoding="utf-8"))


def score(text):
    return analyze(text, online_checks=False)["risk_score"]


KNOWN_MISSES = frozenset(['ar_fresh2_scam_2', 'ar_fresh2_scam_3', 'ar_fresh2_scam_5', 'ar_fresh2_scam_6', 'de_fresh2_scam_3', 'de_fresh2_scam_4', 'de_fresh2_scam_6', 'es_fresh2_scam_3', 'es_fresh2_scam_5', 'fr_fresh2_scam_3', 'fr_fresh2_scam_4', 'fr_fresh2_scam_6', 'fr_fresh_scam_1', 'hi_fresh2_scam_3', 'hi_fresh2_scam_4', 'hi_fresh2_scam_6', 'pt_fresh2_scam_5', 'pt_fresh2_scam_6', 'th_fresh2_scam_2', 'th_fresh2_scam_3', 'th_fresh2_scam_5', 'tl_fresh2_scam_5', 'tl_fresh2_scam_6', 'vi_fresh2_scam_2', 'vi_fresh2_scam_3', 'vi_fresh2_scam_5'])
# 216 genuine messages (24 per language) covering the situations where a genuine message quotes or negates scam wording: fraud warnings,
# fund disclosures, loan and grant notices, HR and payroll notices, bank notices, exchange security notices, quotes with a deposit,
# freelance contracts and scam-awareness talks. The engine wrongly flagged 20 of them (9%) before the warning cues were widened.
GENUINE = json.loads((Path(__file__).parent / "data" / "multilingual_genuine_cases.json").read_text(encoding="utf-8"))


class NineLanguageCaseTests(unittest.TestCase):
    def test_every_scam_is_flagged_except_the_known_misses(self):
        missed = set()
        for case in (c for c in CASES if c["label"] == "SCAM"):
            if analyze(case["text"], online_checks=False)["risk_score"] < FLAGGED:
                missed.add(case["id"])
        self.assertEqual(sorted(missed - KNOWN_MISSES), [], "a scam that used to be caught is no longer flagged")
        # A fix should be recorded here: remove it from KNOWN_MISSES.
        self.assertEqual(sorted(KNOWN_MISSES - missed), [], "these are caught now; remove them from KNOWN_MISSES")

    def test_no_genuine_message_in_the_genuine_set_is_flagged(self):
        flagged = []
        for case in GENUINE:
            if analyze(case["text"], online_checks=False)["risk_score"] >= FLAGGED:
                flagged.append((case["id"], case["class"]))
        self.assertEqual(flagged, [])

    def test_no_genuine_message_is_flagged(self):
        for case in (c for c in CASES if c["label"] == "BENIGN"):
            with self.subTest(id=case["id"], cls=case["class"]):
                result = analyze(case["text"], online_checks=False)
                self.assertLess(result["risk_score"], FLAGGED, [f["id"] for f in result["findings"]])


class HowTheRulesBehaveTests(unittest.TestCase):
    def ids(self, text):
        return {f["id"] for f in analyze(text, online_checks=False)["findings"]}

    def test_a_message_typed_without_accents_matches_like_the_accented_one(self):
        accented = "Para emitir tu contrato y el permiso de trabajo debes abonar 180 EUR de tasas de tramitación por Bizum antes del viernes."
        plain = "Para emitir tu contrato y el permiso de trabajo debes abonar 180 EUR de tasas de tramitacion por Bizum antes del viernes."
        self.assertIn("es_job_fee", self.ids(accented))
        self.assertIn("es_job_fee", self.ids(plain))

    def test_vietnamese_with_and_without_tone_marks_is_one_spelling(self):
        marked = "Anh vui lòng chuyển khoản 1.500.000đ phí hồ sơ và đồng phục để nhận thư mời làm việc."
        plain = "Anh vui long chuyen khoan 1.500.000d phi ho so va dong phuc de nhan thu moi lam viec."
        self.assertIn("vi_job_fee", self.ids(marked))
        self.assertIn("vi_job_fee", self.ids(plain))

    def test_a_web_address_does_not_split_a_sentence(self):
        # "connect your wallet at nova-claim.xyz and approve the contract" - the dot in the address is not a sentence end.
        self.assertIn("es_wallet", self.ids("Reclama tu airdrop de 5.000 tokens NOVA. Conecta tu wallet en nova-claim.xyz y aprueba el contrato para recibir los tokens."))

    def test_thai_sara_am_matches_after_the_engines_unicode_normalisation(self):
        # NFKC splits the Thai vowel U+0E33 in two; a pattern that kept it whole never matched words such as ชำระ ("pay").
        self.assertIn("th_withdraw_fee", self.ids("ยอดเงินในบัญชีของคุณตอนนี้ 320,000 บาท หากต้องการถอน ต้องชำระภาษีกำไร 20% (64,000 บาท) เข้าบัญชีบริษัทก่อน"))

    def test_english_text_does_not_trigger_the_thai_or_tagalog_rules(self):
        # Thai and Tagalog messages mix in "guaranteed", "wallet", "approve"; English text must not match them.
        for text in (
            "Investment returns are not guaranteed. All investments carry risk and you may lose money.",
            "Your crypto wallet provider has updated its app. Never approve an unlimited token allowance for a site you do not trust.",
        ):
            with self.subTest(text=text[:40]):
                self.assertFalse({i for i in self.ids(text) if i.startswith(("th_", "tl_"))})

    def test_a_recovery_scam_that_says_fraud_is_not_taken_for_a_warning(self):
        # "fraude" describes what happened to the victim; only a negation or a warning phrase is a cue.
        self.assertIn("es_recovery", self.ids("Somos la Unidad de Recuperación de Activos Digitales. Localizamos su dinero perdido en el fraude de criptomonedas (12.400 EUR). Para iniciar el proceso solo debe abonar 600 EUR de gastos legales."))

    def test_a_warning_in_another_latin_language_still_counts(self):
        # The French "guaranteed" rule fires on Spanish text ("garantizada"); the Spanish warning must be recognised by it.
        self.assertFalse({i for i in self.ids("Este producto no ofrece rentabilidad garantizada y puede perder parte del capital invertido. No existen rendimientos garantizados.") if i.endswith("_guaranteed")})

    def test_a_fold_keeps_offsets_for_latin_text(self):
        text = "Depósito de garantía"
        self.assertEqual(len(fold_for_matching(text)), len(text))
        self.assertEqual(fold_for_matching(text), "Deposito de garantia")

    def test_a_short_job_word_inside_a_longer_word_is_not_a_job(self):
        # "presupuesto" (a quote) contains "puesto" (a post); a genuine renovation quote with a deposit must not read as a job-fee scam.
        text = "Presupuesto reforma cocina nº 2291: total 6.480 € IVA incluido. Para reservar fecha pedimos un depósito del 20 % (1.296 €) por transferencia a la cuenta del presupuesto. Garantizamos los materiales durante 5 años, según contrato."
        self.assertNotIn("es_job_fee", self.ids(text))
        self.assertLess(score(text), FLAGGED)

    def test_a_genuine_overdraft_notice_is_not_a_task_scam(self):
        # The older English negative_balance rule fired on any negative balance; a genuine notice says why.
        text = "Payroll notice: Ang iyong account ay may negative balance na P350 dahil sa bank charges. Ang issued check para sa iyong final pay ay ide-deposit sa Biyernes. HR, Santos Logistics Inc."
        self.assertLess(score(text), FLAGGED, self.ids(text))

    def test_the_email_password_and_the_returned_deposit_are_recognised(self):
        self.assertIn("es_mail_password", self.ids("Para completar tu onboarding entra en el portal rrhh-amazon-empleo.com e inicia sesión con tu correo y la contraseña de tu email."))
        self.assertIn("pt_refund_lure", self.ids("pra sacar a comissao vc precisa concluir a tarefa e depositar 200 reais via pix, devolvemos junto com o lucro"))

    def test_german_typed_without_umlauts_matches(self):
        # People type "ue/ae/oe" for u-umlaut etc.: "Ueberweisung", "Gebuehr", "fuer".
        self.assertIn("de_withdraw_fee", self.ids("Zur Freigabe ist eine Sicherheitsgebuehr von 1.900 Euro per Ueberweisung auf das Treuhandkonto erforderlich."))

    def test_a_scam_awareness_talk_that_poses_the_scam_as_a_question_is_not_a_scam(self):
        # The scam is in one sentence and "Fuyez" in the next; fraud words and "how to recognise scams" count as a warning.
        text = "Atelier lycée : reconnaître les arnaques en ligne. Un job qui demande un dépôt, ou des gains garantis pour liker des vidéos ? Fuyez, et prévenez un adulte ou le CPE."
        self.assertLess(score(text), FLAGGED)

    def test_but_saying_it_is_not_a_scam_beside_the_offer_is_no_warning(self):
        # A scam says "this is not a scam" right next to its offer; a fraud noun in the NEXT sentence must not switch the rule off.
        self.assertGreaterEqual(score("Ganancias garantizadas del 10% diario, invierte hoy en nuestra plataforma. ¡No es una estafa, miles ya retiraron su dinero!"), FLAGGED)

    def test_fraud_words_do_not_hide_a_recovery_scam(self):
        # The rules that read the whole message ignore fraud nouns: "you were the victim of fraud" is how a recovery scam opens.
        self.assertGreaterEqual(score("Somos la Unidad de Recuperación de Activos Digitales. Localizamos su dinero perdido en el fraude de criptomonedas (12.400 EUR). Para iniciar el proceso solo debe abonar 600 EUR de gastos legales."), FLAGGED)

    def test_a_payout_is_not_a_payment_demand(self):
        # "Auszahlung" (a payout) contains "zahl"; a genuine loan disbursed in instalments is not a demand to pay.
        self.assertLess(score("Bewilligungsbescheid Förderprogramm: 20.000 € Zuschuss, Auszahlung nach Meilensteinen. Es wird ein Eigenanteil von 25 % erwartet. Die Antragstellung ist kostenfrei."), FLAGGED)

    def test_a_booking_receipt_is_not_a_job_fee_in_tagalog_or_thai(self):
        for text in (
            "Confirmed na ang venue booking sa kasal mo sa Dec 12. Natanggap na ang P10,000 reservation deposit; ang balance ay dapat bayaran 2 linggo bago. Ibabalik ang security deposit kung walang sira.",
            "ยืนยันการจองสถานที่จัดงานแต่งวันที่ 12 ธ.ค. ได้รับเงินมัดจำ 10,000 บาทแล้ว ส่วนที่เหลือชำระก่อนงาน 15 วัน เงินประกันความเสียหายจะคืนหากไม่มีความเสียหาย",
        ):
            with self.subTest(text=text[:40]):
                self.assertLess(score(text), FLAGGED, self.ids(text))

    def test_free_is_not_a_no_fee_cue_because_scams_advertise_free_tokens(self):
        self.assertGreaterEqual(score("แจกโทเคนฟรี 5,000 เหรียญ! เชื่อมต่อกระเป๋า MetaMask กับเว็บนี้แล้วกด Approve เพื่อรับรางวัล วันนี้เท่านั้น"), FLAGGED)

    def test_a_genuine_overdraft_or_returned_cheque_notice_is_not_a_task_scam(self):
        for text in (
            "Metrobank: negative balance ang account mo ng P350 dahil sa maintaining balance fee. Mag-deposit bago Lunes para maiwasan ang karagdagang charges. Tingnan sa official app.",
            "Na-return ang cheque na dineposito mo noong 10th dahil sa insufficient funds; nai-debit na sa account mo. Lumipat na ng address ang branch, pareho pa rin ang account number.",
        ):
            with self.subTest(text=text[:40]):
                self.assertLess(score(text), FLAGGED, self.ids(text))

    def test_the_fake_exchange_verification_deposit_is_caught(self):
        self.assertIn("es_verify_deposit", self.ids("Soporte Binance: su cuenta fue restringida por actividad sospechosa. Para verificar su billetera debe hacer un depósito de verificación de 300 USDT a la dirección indicada; se reembolsa en 10 minutos."))

    def test_a_rule_with_no_vocabulary_is_skipped_not_matched_everywhere(self):
        from rules_multilingual import alt
        with self.assertRaises(KeyError):
            alt()


if __name__ == "__main__":
    unittest.main()
