# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Job and investment scam rules for Spanish, French, Portuguese, German, Vietnamese, Tagalog, Hindi, Arabic and Thai.

Before this module the engine read English, Chinese, Malay/Indonesian and Tamil, and caught 1 of 45 scams written in these nine
languages. The rules are built the same way in every language: a short vocabulary per language (what a fee, a payment, "negative
balance", "guaranteed" and so on look like there) is plugged into a dozen scam shapes, and a shape matches when ALL its parts are in ONE
sentence (or, for shapes a scammer spreads over several sentences, anywhere in the message), in any order. "Any order" is what makes
it work across German (verb last), Thai and Hindi, without a grammar per language.

A per-language warning guard (`warn`) then drops a match whose sentence negates or reports the scam, because the genuine messages
in these languages are full of the same words: "nunca pedimos dinero", "aucun frais", "kostenlos", "không bao giờ yêu cầu".
Its cues are negations and warning phrases, deliberately NOT bare fraud nouns ("fraude", "Betrug", "golpe"): a recovery scam says
"you were the victim of fraud" and must not be mistaken for a warning by that word. People-nouns (scammers, fraudsters) do count.

A language's rules only apply to a message written in that language (`_MARKERS`), because Thai and Tagalog messages mix in English
words and English text would otherwise match them.

Patterns are written in natural spelling and folded at build time (accents, Vietnamese tone marks and Arabic vowel marks removed),
and matched against the folded text, so a message typed without accents matches too. German is folded once more (ae/oe/ue to a/o/u)
because people type it without umlauts as "ueberweisen", "fuer", "Gebuehr".
"""
from __future__ import annotations

import re
import unicodedata

from normalization import fold_for_matching
from rules import A_INV, A_JOB, A_PAY, Rule

# A character inside one sentence. A "." is the end of one only when whitespace follows it: not the "." in "1.850", "nova-claim.xyz" or "3.2".
_S = r"(?:[^.!?\n।]|\.(?=\S))"
_START = r"(?:^|(?<=[.!?\n।]))"

_CURR = (r"(?:eur\w*|€|usd|us\$|\$|mxn|cop|ars|clp|pen|brl|r\$|gbp|£|chf|vnd|vnđ|₫|đồng|dong|d\b|k\b|triệu|trieu|thb|baht|บาท|php|₱|peso\w*|"
         r"aed|sar|dirham\w*|dollars?|riyal|inr|₹|rs\.?|rupees?|रुपये|रुपए|रु\b|درهم|ريال|دولار|جنيه|دينار|lakh|लाख|mio\.?|euro|reais|usdt|usdc|btc|eth|"
         r"(?<![a-z])p(?=\s?\d))")
AMT = rf"(?:\d[\d.,]*\s?{_CURR}|{_CURR}\s?\d)"
PCT = r"\d[\d.,]*\s?%"
# A minus sign in front of an amount: the "-142 €" a task scam shows as your "balance".
NEGAMT = rf"(?<!\w)-\s?\d[\d.,]*\s?{_CURR}"
# "+300%", "x10", "10x": the gain a pump group promises.
GAIN = r"\+\s?\d{2,4}\s?%|\bx\s?\d{1,3}\b|\b\d{1,3}\s?x\b"


def conj(*parts: str, scope: str = "sentence") -> str:
    """A pattern that matches a sentence (or, for scope="message", the whole text) containing every part, in any order."""
    if scope == "message":
        return "^" + "".join(f"(?=.*?(?:{p}))" for p in parts) + ".*"
    return _START + "".join(f"(?={_S}*?(?:{p}))" for p in parts) + f"{_S}+"


def alt(*patterns: str) -> str:
    if not patterns:
        raise KeyError("no vocabulary for any alternative")  # an empty pattern would match every message
    return "|".join(f"(?:{p})" for p in patterns)


def fold_german(text: str) -> str:
    """ae/oe/ue -> a/o/u, so "Ueberweisung" and "Überweisung" (already folded to "Uberweisung") are one spelling."""
    return re.sub(r"(?i)([aou])e", r"\1", text)


# --------------------------------------------------------------------------------------------------------------------
# Vocabulary. Keys are the parts the shapes below are built from; a language may leave a key out (that shape is then skipped).
# --------------------------------------------------------------------------------------------------------------------
LEX: dict[str, dict[str, str]] = {
    "es": dict(
        pay=r"pag\w*|abon\w*|deposit\w*|transfier\w*|transfer\w*|envi\w*|ingres\w*|recarg\w*|bizum|consign\w*",
        fee=r"tasas?|cuotas?|tarifas?|comision\w*|gastos?|fianza|garantia|anticipo|impuestos?|deposito|costos?|costes?|seguro",
        # Job words are about a job OFFER: a bare "contrato" or "trabajo" is also a renovation quote ("... depósito del 20 %, según contrato").
        job=r"contrato de trabajo|permiso de trabajo|carta de oferta|oferta de trabajo|oferta laboral|\bpuesto\b|\bvacante\b|\bempleo\b|contratacion|seleccionad[oa]|capacitacion|uniforme",
        neg_bal=r"saldo\s+(?:\w+\s+){0,2}negativ\w*|saldo en negativo|en negativo|numeros rojos", topup=r"recarg\w*|deposit\w*|ingres\w*|abon\w*|pag\w*",
        unlock=r"desbloque\w*|tareas?|pedidos?", withdraw=r"retir\w*|cobrar|sacar", wd_fee=r"impuestos?|tasas?|comision\w*|cuotas?|gastos?",
        task=r"tareas?|misiones?|pedidos?\s+combinad\w*", activate=r"desbloque\w*|activ\w*|valid\w*", unlockfunds=r"desbloque\w*|liber\w*",
        perday=r"al\s+dia|por\s+dia|diari\w+|cada\s+dia|a\s+la\s+semana|por\s+semana|semanal\w*|por\s+hora",
        refund=r"reembols\w*|devolv\w*|devuelv\w*|devolucion|se\s+devuelve", verify=r"verific\w*|confirm\w*",
        mailpass=r"contrasena\s+(?:de\s+)?(?:tu|su|del)\s+(?:correo|email|e-?mail|gmail|outlook)|(?:correo|email|e-?mail)\s+(?:personal\s+)?y\s+(?:la\s+)?contrasena",
        guar=r"garantiz\w*|garantiza\w*|riesgo cero|cero riesgo|sin riesgo|100 ?% (?:seguro|asegurado)|capital (?:asegurado|garantizado|protegido)",
        ctx=r"invers\w*|rentabilidad|ganancia\w*|beneficio\w*|rendimiento\w*|capital|retorno|interes\w*|gana\w*|rinde|rende",
        recv=r"recib\w*\s+(?:\w+\s+){0,2}(?:pagos|transferencias|dinero|fondos)|(?:pagos|transferencias|dinero)\s+(?:en|a)\s+(?:tu|su)\s+cuenta",
        fwd=r"reenv\w*|transfier\w*|transfer\w*|enviar\w*|reenvi\w*", parcel=r"recib\w*\s+(?:\w+\s+){0,2}(?:paquetes|paquete|pedidos|encomiendas)", reship=r"reenv\w*|reembal\w*|reempaquet\w*|al extranjero",
        send=r"envi\w*|manda\w*|comparte\w*|proporcion\w*|facilit\w*|sube\w*|adjunt\w*",
        doc=r"foto\s+de\s+tu\s+(?:dni|pasaporte|documento|cedula|ine|curp|identificacion)|ambas\s+caras|(?:dni|pasaporte|cedula|curp)\b.{0,30}\bfoto",
        otp=r"codigo.{0,30}(?:sms|verificacion|seguridad|bancario|token)|contrasena|otp|\bpin\b", acct=r"numero\s+de\s+cuenta|cuenta\s+bancaria|iban|clabe",
        lost=r"perdid\w*|robad\w*|estafad\w*|defraudad\w*", recover=r"recuper\w*|reclam\w*|rastre\w*|localiz\w*",
        loan=r"prestamo|credito|subvencion|beca|herencia|premio|financiacion", release=r"liber\w*|desembols\w*",
        newacct=r"nuev[ao]\s+(?:cuenta|iban|datos bancarios)", old=r"antigu[ao]\s+(?:cuenta|iban)|(?:cuenta|iban)\s+(?:antigu\w*|anterior)|desactiv\w*|bloquead\w*|anulad\w*",
        wallet=r"conect\w*\s+(?:tu\s+|su\s+)?(?:cartera|wallet|billetera)|(?:cartera|wallet|billetera).{0,30}conect\w*", approve=r"aprueb\w*|aprobar|autoriz\w*|permis\w*",
        pump=r"pump|preventa|senales|grupo\s+vip",
        cheque=r"cheque", buy=r"compr\w*|adquir\w*", equip=r"equipo|laptop|ordenador|material|proveedor\w*|suministr\w*",
        warn=r"\b(?:nunca|jamas)\b|\bno\s+(?:se\s+)?(?:te\s+|le\s+|les\s+)?(?:cobr\w*|pid\w*|solicit\w*|exig\w*|requier\w*)|\bninguna?\s+(?:cuota|tasa|comision|deposito|pago|gasto|cargo)|\bsin\s+(?:ningun\s+)?(?:coste|costo|cargo|cuota|comision|gasto)s?\b|\bgratuit\w*|\bestafadores\b|\baviso de (?:seguridad|riesgo)|\balerta\b|\bante la duda|\bdesconf\w*|\bcuidado\b|\bsi\s+alguien\b|\bno\s+(?:garantiz\w*|ofrece\s+rentabilidad)|\bno\s+(?:existen?|hay)\s+(?:\w+\s+){0,2}garantiz\w*|\brentabilidades?\s+pasadas?|\banualizada historica|\balto\s+riesgo|\bpodria\s+perder|\bpuede\s+perder|\bes\s+una\s+estafa|\bsi\s+(?:te|le)\s+prometen",
    ),
    "fr": dict(
        pay=r"pay\w*|regl\w*|verse\w*|vire\w*|virement|transf\w*|deposer|depos\w*|envoy\w*|recharg\w*|acquitt\w*|exig\w*|demand\w*",
        fee=r"frais|taxes?|droits?|redevance|caution|depot de garantie|acompte|commission|assurance|impots?|cout",
        job=r"contrat de travail|permis de travail|lettre d'offre|offre d'emploi|\bposte\b|\bemploi\b|embauch\w*|recrut\w*|formation|uniforme",
        neg_bal=r"solde\s+(?:\w+\s+){0,3}(?:negatif|debiteur)|en negatif", topup=r"recharg\w*|deposer|depos\w*|verse\w*|alimenter", unlock=r"debloqu\w*|tache\w*|mission\w*",
        withdraw=r"retir\w*|encaiss\w*", wd_fee=r"impots?|taxes?|frais|commission|droits",
        task=r"tache\w*|mission\w*|commandes?\s+combinee", activate=r"debloqu\w*|activ\w*|valider", unlockfunds=r"debloqu\w*|liber\w*",
        perday=r"par\s+jour|par\s+semaine|quotidien\w*|hebdomadaire|par\s+heure|chaque\s+jour",
        refund=r"rembours\w*|restitu\w*|rendons|vous\s+sera\s+rendu", verify=r"verifi\w*|confirm\w*",
        mailpass=r"mot\s+de\s+passe\s+(?:de\s+)?(?:votre\s+|ta\s+|ton\s+)?(?:boite\s+mail|e-?mail|messagerie|adresse\s+mail|gmail|outlook)|(?:boite\s+mail|e-?mail|messagerie)\s+et\s+(?:le\s+)?mot\s+de\s+passe",
        guar=r"garanti\w*|zero risque|sans risque|aucun risque|100\s?%\s+securise|capital\s+(?:\d+\s?%\s+)?(?:securise|garanti|protege)|rendement\s+assure",
        ctx=r"invest\w*|rendement|gain\w*|profit\w*|benefice\w*|capital|interet\w*|placement|rapporte",
        recv=r"recev\w*\s+(?:\w+\s+){0,2}(?:virements|paiements|fonds|argent)|(?:virements|paiements|fonds)\s+sur\s+votre\s+compte",
        fwd=r"transf\w*|renvoy\w*|reexpedi\w*|reverse\w*", parcel=r"recev\w*\s+(?:\w+\s+){0,2}(?:colis|paquets)|gestionnaire\s+de\s+colis", reship=r"reconditionn\w*|renvoy\w*|reexpedi\w*|a l'etranger",
        send=r"envoy\w*|transmet\w*|partag\w*|communiq\w*|fourni\w*|adress\w*",
        doc=r"(?:photo|copie|scan)\s+de\s+(?:votre|ta|vos)\s+(?:cni|carte\s+d'identite|passeport|piece\s+d'identite)|recto[\s-]*verso|deux\s+faces|carte\s+d'identite|piece\s+d'identite|identifiants",
        otp=r"code.{0,30}(?:sms|verification|securite|recu)|mot\s+de\s+passe|otp", acct=r"numero\s+de\s+compte|iban|\brib\b",
        lost=r"perdu\w*|vole\w*|escroqu\w*|arnaque\w*", recover=r"recuper\w*|retrouv\w*",
        loan=r"pret|credit|subvention|bourse|heritage|aide", release=r"debloqu\w*|liber\w*|verser|versement",
        newacct=r"nouveau\s+(?:compte|rib|iban)", old=r"ancien\s+(?:compte|rib|iban)|desactiv\w*|bloque\w*",
        wallet=r"connect\w*\s+(?:votre\s+|ton\s+|ta\s+)?(?:portefeuille|wallet)|(?:portefeuille|wallet).{0,30}connect\w*", approve=r"approuv\w*|autoris\w*|validez|signez",
        pump=r"pump|pomp\w*|prevente|signaux|groupe\s+vip",
        cheque=r"cheque", buy=r"achet\w*|acquer\w*", equip=r"materiel|equipement|fournisseur|ordinateur",
        warn=r"\bjamais\b|\bne\s+(?:vous\s+)?(?:demand\w*|factur\w*|exig\w*|reclam\w*)|\baucun(?:e)?s?\s+(?:\w+\s+)?(?:frais|paiement|depot|cout|somme|versement|rendement)|\bgratuit\w*|\bsans\s+frais|\bmefi\w*|\bfaux\s+conseiller|\ben\s+cas\s+de\s+doute|\bsi\s+quelqu'un|\bperformances?\s+passees|\bne\s+prejugent|n'est\s+(?:pas\s+)?garanti|\bnon\s+garanti|\bne\s+(?:garanti|promet)|\brisque\s+eleve|\bperte\s+en\s+capital|\bpouvez\s+perdre|\bfraudeurs\b|\bescrocs\b|\bsi\s+on\s+vous\s+promet|c'est\s+une\s+arnaque|\bconseil\s+de\s+prevention",
    ),
    "pt": dict(
        pay=r"pag\w*|deposit\w*|transfer\w*|envi\w*|\bpix\b|recarg\w*|repass\w*",
        fee=r"taxas?|tarifas?|comiss\w*|imposto\w*|caucao|garantia|adiantamento|custos?|seguro|inscric\w*",
        job=r"carta de oferta|contrato de trabalho|\bvaga\b|\bemprego\b|exame admissional|treinamento|uniforme|contratad[oa]|selecionad[oa]|aprovad[oa]",
        neg_bal=r"saldo\s+(?:\w+\s+){0,2}negativ\w*|no vermelho", topup=r"recarga|recarreg\w*|\bpix\b|deposit\w*|pag\w*", unlock=r"liber\w*|desbloque\w*|tarefas?|missoes|missao",
        withdraw=r"saque|sacar|retirar|resgat\w*", wd_fee=r"imposto\w*|taxas?|comiss\w*|\biof\b|tarifa",
        task=r"tarefas?|missoes|missao", activate=r"liber\w*|desbloque\w*|ativ\w*|valid\w*", unlockfunds=r"liber\w*|desbloque\w*",
        perday=r"ao\s+dia|por\s+dia|diari\w+|por\s+semana|ao\s+semana|semanal\w*|por\s+hora",
        refund=r"devolv\w*|reembols\w*|devolucao", verify=r"verific\w*|confirm\w*",
        mailpass=r"senha\s+(?:do|de)\s+(?:seu\s+|sua\s+)?(?:e-?mail|correio|gmail|outlook)|(?:e-?mail|correio)\s+e\s+(?:a\s+)?senha",
        guar=r"garant\w*|sem risco|risco zero|zero risco|100 ?% seguro|capital (?:garantido|protegido)",
        ctx=r"invest\w*|rentabilidade|lucro\w*|rendiment\w*|retorno|ganho\w*|capital|juros|rende",
        recv=r"receb\w*\s+(?:\w+\s+){0,2}(?:pagamentos|transferencias|dinheiro|valores)|pagamentos.{0,30}na\s+sua\s+conta",
        fwd=r"repass\w*|transfer\w*|encaminh\w*", parcel=r"receb\w*\s+(?:\w+\s+){0,2}(?:encomendas|pacotes|produtos)", reship=r"reenvi\w*|reembal\w*|para o exterior",
        send=r"envi\w*|manda\w*|informe\w*|passe\w*|compartilh\w*|fotografe|foto",
        doc=r"(?:foto|fotografia)\s+d[oae]\s+(?:seu\s+)?(?:rg|cpf|cnh|documento|passaporte)|frente e verso|ambos os lados",
        otp=r"codigo.{0,30}(?:sms|verificacao|seguranca|token)|senha|token|otp", acct=r"numero da conta|conta bancaria|agencia",
        lost=r"perd\w*|roub\w*|golp\w*|fraud\w*", recover=r"recuper\w*|resgat\w*|localiz\w*|rastre\w*",
        loan=r"emprestimo|credito|subsidio|heranca|premio|financiamento|fomento", release=r"liber\w*|desembols\w*",
        newacct=r"nova\s+conta|novos?\s+dados\s+bancarios|nova\s+chave\s+pix", old=r"conta\s+antiga|antiga\s+conta|desativ\w*|bloquead\w*",
        wallet=r"conecte\w*\s+(?:sua\s+)?carteira|carteira.{0,40}conect\w*|wallet", approve=r"aprove\w*|autoriz\w*|permiss\w*|assine",
        pump=r"\bpump\b|pre-?venda|sinais|grupo\s+vip",
        cheque=r"cheque", buy=r"compr\w*", equip=r"equipamento\w*|notebook|computador|fornecedor|material",
        warn=r"\b(?:nunca|jamais)\b|\bnao\s+(?:cobr\w*|pedi\w*|solicit\w*|exig\w*)|\bnenhum\w*\s+(?:taxa|cobranca|deposito|custo)|\bsem\s+(?:custo|taxa|cobranca)|\bgratuit\w*|\bgolpistas\b|\balerta\b|\bcuidado|\bse\s+alguem|\bdesconf\w*|\bnao\s+e\s+garantia|\bnao\s+garant\w*|\brentabilidade\s+(?:passada|historica)|\bnao\s+conta\s+com\s+garantia|\bnao\s+ha\s+(?:cobranca|garantia)|\bperda\s+do\s+capital|\bpossibilidade\s+de\s+perda|\bpode\s+gerar\s+perdas|\be\s+golpe\b|\bse\s+(?:te|lhe)\s+prometerem",
    ),
    "de": dict(
        pay=r"uberweis\w*|zahl\w*|einzahl\w*|bezahl\w*|aufladen|senden|uberweisung|hinterleg\w*|paysafecard",
        fee=r"gebuhr\w*|kosten|kaution|vorauszahlung|steuer\w*|provision|abgabe|versicherung|anzahlung",
        job=r"arbeitserlaubnis|arbeitsvertrag|\bstelle\b|\bjob\b|nebenjob|schulung\w*|arbeitsplatz|bewerbung|einstellung|uniform|vertragsbeginn",
        neg_bal=r"im\s+minus|negativ\w*", topup=r"aufladen|einzahlen|nachladen|zahl\w*", unlock=r"freischalt\w*|aufgaben?",
        withdraw=r"auszahl\w*|abheb\w*|entnehm\w*", wd_fee=r"steuer\w*|gebuhr\w*|kosten|provision|abgabe",
        task=r"aufgaben?|mission\w*|kombi\w*", activate=r"freischalt\w*|aktivier\w*|freigeb\w*", unlockfunds=r"freigab\w*|freigeb\w*|freischalt\w*|entsperr\w*",
        perday=r"pro\s+tag|taglich|pro\s+woche|wochentlich|am\s+tag|pro\s+stunde",
        refund=r"zuruckerstatt\w*|erstatt\w*|zuruckgezahlt|zuruckzahl\w*|zuruckerhalt\w*|zuruck\s+erhalten", verify=r"verifizier\w*|bestatig\w*|verifikation",
        mailpass=r"e-?mail-?passwort|passwort\s+(?:ihres|ihrer|deines|des)\s+(?:e-?mail|postfach|mail)|(?:e-?mail|e-?mail-?adresse)\s+und\s+(?:ihrem\s+|dein\s+)?(?:e-?mail-?)?passwort",
        guar=r"garantiert\w*|garantie\w*|risikofrei|ohne\s+risiko|kein\s+risiko|100\s?%\s+sicher|kapital.{0,20}sicher",
        ctx=r"rendite\w*|gewinn\w*|ertrag\w*|zins\w*|invest\w*|kapital|verdien\w*",
        recv=r"(?:erhalten|empfangen)\s+(?:\w+\s+){0,2}zahlungen|zahlungen.{0,40}auf\s+ihr\s+konto|finanzagent\w*|geldeingang\w*|entgegennehm\w*",
        fwd=r"weiterleit\w*|weitersend\w*|uberweis\w*|weitergeb\w*|leit\w*\s+.{0,40}weiter", parcel=r"pakete?\s+an\w*|nehmen\s+sie\s+pakete\s+an|paket\w*\s+annehm\w*",
        reship=r"versend\w*|weiterversend\w*|ins\s+ausland|nach\s+(?:osteuropa|asien)|weiterleit\w*",
        send=r"senden|schick\w*|ubermittel\w*|teilen|geben|hochlad\w*|mitteil\w*|benotig\w*|brauchen|erforderlich|verlangen|angeben|nennen|zusenden",
        doc=r"(?:foto|kopie|scan)\s+(?:ihres|ihrer|von)\s+(?:personalausweis|ausweis|reisepass|fuhrerschein)|personalausweis|beide\s+seiten|vorder-?\s*und\s*ruckseite",
        otp=r"\b(?:tan|otp|sms-?code|verifizierungscode|bestatigungscode|passwort|pin)\b|banking-?login", acct=r"kontonummer|iban|bankkonto",
        lost=r"verlor\w*|verlust|betrug\w*|abgezockt|gestohlen", recover=r"zuruckhol\w*|wiederbeschaff\w*|zuruckerhalt\w*|ruckerstattung|zuruckfuhr\w*|aufgespurt",
        loan=r"kredit|darlehen|zuschuss|erbschaft|erb(?:e|es|en)\b|hinterliess\w*|gewinn|forderung|finanzierung", release=r"auszahl\w*|freigab\w*|freigeb\w*|freischalt\w*",
        newacct=r"neue[sn]?\s+(?:konto|kontoverbindung|bankverbindung|iban)", old=r"alte[sn]?\s+(?:konto|kontoverbindung|bankverbindung|iban)|gesperrt|nicht\s+mehr\s+gultig",
        wallet=r"wallet|krypto-?geldbeutel", approve=r"freigab\w*|genehmig\w*|bestatig\w*|verbinden|approve", pump=r"\bpump\b|vorverkauf|signalgruppe|vip-?gruppe",
        cheque=r"scheck", buy=r"kauf\w*|besorg\w*|anschaff\w*", equip=r"ausrustung|gerate\w*|lieferant\w*|laptop|material",
        warn=r"\bniemals\b|\b(?:nie|nicht)\s+(?:\w+\s+){0,3}(?:verlang\w*|fordern|fragen|bitten|weitergeb\w*|mitteil\w*)|\bkostenlos\b|\bkeine?\s+(?:gebuhr\w*|kosten|vorauszahlung|kapitalgarantie|garantie)|\bohne\s+gebuhr|\bbetruger\w*|\bsicherheitshinweis|\bwarnung|\bverbraucherwarnung|\bvorsicht|\bwenn\s+jemand|\bkein\s+verlasslicher|\bwertentwicklung\s+in\s+der\s+vergangenheit|\bnicht\s+garantiert|\bunserios|\bverspricht\b|\btotalverlust|\bverluste\s+bis|\bgarantie\s+(?:\w+\s+){0,3}(?:nicht|kein)|\b(?:nicht|kein\w*)\s+(?:\w+\s+){0,2}garantie|\bkapitalverlust",
    ),
    "vi": dict(
        pay=r"chuyen\s+khoan|nop\w*|dong\b|thanh\s+toan|gui\b|dat\s+coc|tra\s+phi|chuyen\b",
        fee=r"\bphi\b|le\s+phi|tien\s+coc|dat\s+coc|thue|bao\s+hiem|tam\s+ung",
        job=r"thu\s+moi\s+lam\s+viec|hop\s+dong|viec\s+lam|vi\s+tri|trung\s+tuyen|tuyen\s+dung|nhan\s+viec|dong\s+phuc|cong\s+viec",
        neg_bal=r"dang\s+am\b|tai\s+khoan.{0,20}\bam\b|so\s+du\s+am|thau\s+chi", topup=r"nap\b|nap\s+(?:them|tien)|chuyen\s+khoan", unlock=r"mo\s+khoa|nhiem\s+vu",
        withdraw=r"\brut\b", wd_fee=r"thue|\bphi\b|le\s+phi",
        task=r"nhiem\s+vu|don\s+hang|don\s+ghep", activate=r"kich\s+hoat|mo\s+khoa|hoan\s+thanh", unlockfunds=r"mo\s+khoa|giai\s+ngan|\brut\b",
        perday=r"moi\s+ngay|mot\s+ngay|/\s?ngay|moi\s+tuan|/\s?tuan|\bngay\b",
        refund=r"hoan\s+lai|hoan\s+tra|tra\s+lai", verify=r"xac\s+minh|xac\s+thuc",
        mailpass=r"mat\s+khau\s+(?:cua\s+)?(?:email|gmail|mail)|(?:email|gmail)\s+va\s+mat\s+khau",
        guar=r"cam\s+ket\s+(?:lai|loi\s+nhuan|thu\s+nhap)|bao\s+dam\s+(?:von|lai|loi)|khong\s+rui\s+ro|zero\s+risk|von\s+100", ctx=r"\blai\b|loi\s+nhuan|dau\s+tu|\bvon\b|thu\s+nhap|sinh\s+loi",
        recv=r"nhan\s+(?:tien|chuyen\s+khoan|thanh\s+toan)|vao\s+tai\s+khoan\s+cua\s+ban", fwd=r"chuyen\s+tiep|chuyen\s+lai|chuyen\s+di",
        parcel=r"nhan\s+(?:hang|goi|kien)", reship=r"gui\s+(?:di\s+)?(?:nuoc\s+ngoai|lai)|dong\s+goi\s+lai",
        send=r"gui\b|cung\s+cap|chup|\banh\b", doc=r"cccd|cmnd|can\s+cuoc|ho\s+chieu|hai\s+mat", otp=r"\botp\b|ma\s+xac\s+(?:nhan|thuc|minh)|mat\s+khau",
        acct=r"so\s+tai\s+khoan|tai\s+khoan\s+ngan\s+hang",
        lost=r"mat\s+tien|bi\s+lua|lua\s+dao|da\s+mat", recover=r"thu\s+hoi|lay\s+lai|tim\s+lai|truy\s+tim",
        loan=r"khoan\s+vay|tai\s+tro|thua\s+ke|trung\s+thuong|giai\s+ngan", release=r"giai\s+ngan|nhan\s+tien|mo\s+khoa",
        newacct=r"tai\s+khoan\s+moi|stk\s+moi", old=r"tai\s+khoan\s+cu|bi\s+khoa",
        wallet=r"vi\s+(?:dien\s+tu|crypto|tien\s+ao|metamask|trust|phantom|binance)|metamask|wallet", approve=r"phe\s+duyet|cap\s+quyen|uy\s+quyen|approve|ket\s+noi", pump=r"\bpump\b|tin\s+hieu|nhom\s+vip",
        cheque=r"\bsec\b", buy=r"\bmua\b", equip=r"thiet\s+bi|nha\s+cung\s+cap|may\s+tinh|laptop",
        warn=r"khong\s+bao\s+gio|khong\s+thu\b|khong\s+yeu\s+cau|mien\s+phi|khong\s+mat\s+phi|canh\s+bao|ke\s+lua\s+dao|nghi\s+ngo|neu\s+ai\s+do|khong\s+cam\s+ket|khong\s+bao\s+dam|ket\s+qua\s+trong\s+qua\s+khu|co\s+the\s+mat",
    ),
    "tl": dict(
        pay=r"magbayad|bayad|mag-?send|i-?gcash|i-?send|ideposito|deposit|transfer|i-?transfer|ipadala|magpadala|padala|bayaran|\bpay\b",
        fee=r"\bfee\b|bayad|\btax\b|deposit|processing|\bbond\b|charge",
        job=r"visa|medical|trabaho|natanggap|hired|\bjob\b|position|deployment|contract|slot|worker",
        neg_bal=r"negative\s+balance|nag-?negative|negative\s+ka", topup=r"top\s*-?up|recharge|deposit|magbayad", unlock=r"unlock|\btask\b|withdraw",
        withdraw=r"withdraw", wd_fee=r"\btax\b|\bfee\b|anti-?money",
        task=r"\btask\b|order", activate=r"unlock|activate", unlockfunds=r"release|i-?release|unlock",
        perday=r"kada\s+araw|kada\s+linggo|araw-araw|per\s+day|a\s+day|daily|weekly",
        refund=r"refund|ibabalik|ibalik|i-?return|maibabalik", verify=r"verif\w*|i-?verify",
        mailpass=r"email\s+password|password\s+ng\s+(?:email|gmail)|email\s+at\s+password",
        guar=r"guaranteed|garantisado|sure\s+win|walang\s+risk|no\s+risk|zero\s+risk|risk-?free", ctx=r"kita|puhunan|return|profit|invest|tubo",
        recv=r"t[au]?tanggap\s+ng\s+(?:pera|bayad|payment)|tanggap\s+ng\s+pera|matanggap\s+sa\s+account", fwd=r"i-?forward|ipasa|ipapasa|i-?transfer",
        parcel=r"t[au]?tanggap\s+ng\s+(?:package|parcel)", reship=r"i-?reship|ipadala\s+sa\s+abroad|i-?repack|ship\s+abroad",
        send=r"ipadala|i-?send|ibigay|i-?share|picture|larawan", doc=r"\bumid\b|passport|national\s+id|\bsss\b|philid|driver'?s?\s+license|valid\s+id|selfie",
        otp=r"\botp\b|password|\bpin\b|6-?digit", acct=r"bank\s+account|account\s+number|gcash\s+number",
        lost=r"nawala|na-?scam|\blost\b|nabiktima|biktima", recover=r"i-?recover|mag-?recover|\brecover|mabawi|ibalik|ibabalik|recovery",
        loan=r"\bloan\b|\bgrant\b|inheritance|pautang|premyo|prize|ayuda|cash\s*aid|subsidy", release=r"release|i-?release|makuha",
        newacct=r"bagong\s+account|new\s+account", old=r"lumang\s+account|old\s+account|closed",
        wallet=r"wallet|i-?connect", approve=r"approve|i-?authorize", pump=r"\bpump\b|pre-?sale|vip\s+group|signals",
        cheque=r"\bcheck\b|\bcheque\b|tseke", buy=r"bumili|bilhin|\bbili\b|\bbuy\b|purchase", equip=r"equipment|laptop|supplier|gadget",
        warn=r"kailanman|\blibre\b|walang\s+(?:application\s+fee|fee|deposit|guarantee|bayad)|babala|\bscammer|huwag\s+(?:ibigay|magbayad|mag-?transfer|ibahagi|i-?share)|paalala|nakaraang\s+performance|hindi\s+garantiya|hindi\s+(?:kami\s+)?(?:naniningil|hihingin)",
    ),
    "hi": dict(
        pay=r"भेजें|भेजिए|जमा\s+करें|जमा\s+करना|ट्रांसफ़र|ट्रांसफर|भुगतान|UPI|पे\s+करें|चुकाएं|रिचार्ज",
        fee=r"फीस|फ़ीस|शुल्क|टैक्स|जीएसटी|GST|सिक्योरिटी|डिपॉज़िट|डिपॉजिट|रजिस्ट्रेशन",
        job=r"ऑफर\s+लेटर|नौकरी|पद\b|जॉइनिंग|ट्रेनिंग|यूनिफॉर्म|भर्ती|सैलरी|चयन",
        neg_bal=r"नेगेटिव|माइनस", topup=r"रिचार्ज|जमा|टॉप\s?अप|top\s?up", unlock=r"टास्क|अनलॉक",
        withdraw=r"निकाल\w*|विड्रॉल|विड्रॉ|निकासी|withdraw", wd_fee=r"टैक्स|जीएसटी|GST|शुल्क|फीस",
        task=r"टास्क|ऑर्डर", activate=r"अनलॉक|एक्टिवेट|सक्रिय|unlock", unlockfunds=r"अनलॉक|रिलीज|unlock",
        perday=r"रोज़|रोज|प्रतिदिन|हर\s+हफ्ते|साप्ताहिक|हर\s+दिन|daily|weekly",
        refund=r"वापस|रिफंड|लौटा|लौट", verify=r"वेरिफ|सत्यापन",
        mailpass=r"ईमेल\s+(?:का\s+|के\s+)?पासवर्ड|पासवर्ड\s+(?:ईमेल|जीमेल)|ईमेल\s+और\s+(?:ईमेल\s+)?(?:के\s+)?पासवर्ड",
        guar=r"गारंटी\w*|ज़ीरो\s+रिस्क|जीरो\s+रिस्क|जोखिम\s+मुक्त|बिना\s+जोखिम|100\s?%\s+सुरक्षित", ctx=r"मुनाफ़ा|मुनाफा|कमाई|रिटर्न|निवेश|लाभ|प्रॉफिट",
        recv=r"पैसे\s+(?:आपके|अपने)\s+खाते\s+में|खाते\s+में\s+पैसे|खाते\s+में\s+(?:\S+\s+){0,3}पैसा", fwd=r"आगे\s+भेज\w*|ट्रांसफ़र\s+कर\w*|फॉरवर्ड|भेजना|भेजने",
        send=r"भेजिए|भेजें|भेज\s+दें|दीजिए|शेयर", doc=r"आधार|पैन\s+कार्ड|वोटर\s+आईडी|फोटो|फ़ोटो|पासपोर्ट", otp=r"OTP|पासवर्ड|पिन", acct=r"बैंक\s+खाता|खाता\s+नंबर|अकाउंट\s+नंबर",
        lost=r"खोए|खोया|ठगी|फ्रॉड|गंवाए", recover=r"वापस|रिकवर|बरामद|ट्रेस",
        loan=r"लोन|ऋण|अनुदान|इनाम|लॉटरी|विरासत", release=r"जारी|रिलीज़|रिलीज",
        newacct=r"नया\s+(?:बैंक\s+)?खाता|नए\s+खाते", old=r"पुराना\s+खाता|बंद",
        wallet=r"वॉलेट|wallet", approve=r"अप्रूव|मंज़ूरी|अनुमति|approve", pump=r"पंप|सिग्नल|वीआईपी\s+ग्रुप",
        cheque=r"चेक", buy=r"खरीद\w*", equip=r"सप्लायर|उपकरण|लैपटॉप|आपूर्तिकर्ता",
        warn=r"कभी\s+(?:\S+\s+){0,4}(?:नहीं|न)|नहीं\s+(?:लेते|लेती|ली\s+जाती|मांगता|माँगता|मांगती|माँगती|मांगते|माँगते|मांगेगा)|न\s+ही\b|निःशुल्क|निशुल्क|मुफ़्त|मुफ्त|कोई\s+शुल्क\s+(?:नहीं|या)|चेतावनी|(?<![ऀ-ॿ])ठग(?![ऀ-ॿ])|जोखिमों?\s+के\s+अधीन|गारंटी\s+नहीं|पिछला\s+प्रदर्शन|किसी\s+को\s+न\s+बताएं|सावधान",
    ),
    "ar": dict(
        pay=r"تحويل|حول|دفع|ادفع|سداد|اودع|ايداع|ارسل|اشحن|شحن",
        fee=r"رسوم|ضريبة|عمولة|تامين|وديعة|كفالة|مصاريف",
        job=r"عقد\s+العمل|تصريح|وظيفة|راتب|توظيف|تدريب|خطاب\s+العرض", neg_bal=r"بالسالب|رصيد\s+سالب|سالب|مديون", topup=r"اشحن|شحن|ايداع|ادفع|اودع", unlock=r"المهمة|مهمة|مهام|تفتح",
        withdraw=r"سحب|تسحب|السحب", wd_fee=r"ضريبة|رسوم|عمولة",
        task=r"المهمة|مهمة|مهام", activate=r"لفتح|تفتح|تفعيل|لاكمال", unlockfunds=r"فك|تحرير|صرف",
        perday=r"يوميا|اسبوعيا|كل\s+يوم|كل\s+اسبوع|في\s+اليوم",
        refund=r"يرجع|ترجع|استرداد|يسترد|تسترد|رد\s+المبلغ", verify=r"تحقق|توثيق",
        mailpass=r"كلمة\s+(?:مرور|سر)\s+(?:البريد|بريدك|الايميل|الاميل)|بريدك\s+الالكتروني\s+و\s*كلمة",
        guar=r"مضمون\w*|ضمان|بدون\s+(?:اي\s+)?مخاطر\w*|صفر\s+مخاطر|بلا\s+مخاطر", ctx=r"ارباح|ربح|عوائد|عائد|استثمر|راس\s+المال|تداول",
        recv=r"استلام\s+(?:الاموال|مدفوعات|تحويلات|حوالات|حوالة)|تستقبل|حوالات", fwd=r"تحويلها|اعادة\s+تحويل|ارسالها",
        parcel=r"استلام\s+(?:طرود|طرد|شحنات)", reship=r"اعادة\s+شحن|شحنها\s+للخارج",
        send=r"ارسل|ارسلي|شارك|قدم|صورة|صور", doc=r"الهوية|جواز|بطاقة", otp=r"رمز\s+التحقق|كلمة\s+المرور|otp|الرقم\s+السري", acct=r"رقم\s+حسابك|حساب\s+بنكي|الحساب\s+البنكي|ايبان",
        lost=r"خسرت|فقدت|احتيال|نصب", recover=r"استرداد|استعادة|استرجاع",
        loan=r"قرض|منحة|ميراث|جائزة", release=r"صرف|تحرير|الافراج|تسليم|استلام",
        newacct=r"حساب\s+جديد", old=r"الحساب\s+القديم|محظور|مجمد|مغلق",
        wallet=r"محفظ\w*|wallet", approve=r"وافق|موافقة|اسمح|تفويض|approve", pump=r"pump|بامب|اشارات|مجموعة\s+vip",
        cheque=r"شيك", buy=r"اشتر\w*|شراء", equip=r"المعدات|معدات|المورد|جهاز|لابتوب",
        warn=r"لا\s+(?:تشارك|تحول|تدفع|نطلب|تطلب|يطلب|نقوم|يمثل|نقدم|نضمن|تضمن)|لن\s+(?:تطلب|نطلب)|ابدا|مجاني\w*|بدون\s+رسوم|لا\s+(?:توجد|يوجد)\s+(?:اي\s+)?(?:رسوم|ودائع|ضمانات|ضمان)|تنبيه|تحذير|المحتال\w*|الاداء\s+السابق|ليس\s+(?:مؤشرا|ضمانا)|لا\s+ضمان|افصاح",
    ),
    "th": dict(
        pay=r"โอน|ชำระ|จ่าย|เติมเงิน|วางเงิน|ส่งเงิน|ฝากเงิน",
        fee=r"ค่า(?:ดำเนินการ|ธรรมเนียม|สมัคร|มัดจำ|ชุด|อบรม|ประกัน)|เงินมัดจำ|ภาษี",
        job=r"ตำแหน่ง|จดหมายเสนองาน|สัญญาจ้าง|ใบอนุญาตทำงาน|เงินเดือน|สมัครงาน|งาน",
        neg_bal=r"ติดลบ", topup=r"เติมเงิน|ฝากเงิน|เติมยอด|top\s?up", unlock=r"ปลดล็อก|งานถัดไป",
        withdraw=r"ถอน", wd_fee=r"ภาษี|ค่าธรรมเนียม",
        task=r"ภารกิจ|งานถัดไป|ออเดอร์", activate=r"ปลดล็อก|เปิดใช้งาน|ยืนยัน", unlockfunds=r"ปลดล็อก|ปล่อย",
        perday=r"ต่อวัน|วันละ|ต่อสัปดาห์|สัปดาห์ละ|ต่อชั่วโมง",
        refund=r"คืน|รีฟันด์", verify=r"ยืนยัน|ตรวจสอบ",
        mailpass=r"รหัสผ่าน(?:ของ)?อีเมล|อีเมล(?:และ|กับ)รหัสผ่าน",
        guar=r"การันตี|รับประกัน|ไม่มีความเสี่ยง|ปลอดภัย\s?100|ไม่เสี่ยง", ctx=r"ผลตอบแทน|กำไร|ลงทุน|เงินต้น|ดอกเบี้ย",
        recv=r"รับเงิน|รับโอน", fwd=r"โอนต่อ|ส่งต่อ|โอนไป",
        send=r"ส่ง|แจ้ง|ให้", doc=r"บัตรประชาชน|พาสปอร์ต|หนังสือเดินทาง", otp=r"OTP|รหัส|พิน", acct=r"เลขบัญชี|บัญชีธนาคาร",
        lost=r"สูญเงิน|ถูกหลอก|โดนโกง|เสียเงิน", recover=r"ทวงคืน|เรียกคืน|กู้คืน|เงินคืน|ติดตาม",
        loan=r"เงินกู้|สินเชื่อ|มรดก|รางวัล", release=r"ปล่อย|อนุมัติ",
        newacct=r"บัญชีใหม่", old=r"บัญชีเก่า|ระงับ",
        wallet=r"กระเป๋า|wallet", approve=r"อนุมัติ|approve", pump=r"pump|สัญญาณ|กลุ่ม\s?VIP",
        cheque=r"เช็ค|เช็ก", buy=r"ซื้อ", equip=r"อุปกรณ์|ซัพพลายเออร์|ผู้ขาย|โน้ตบุ๊ก|คอมพิวเตอร์",
        warn=r"ไม่เคย(?:ขอ|เก็บ|เรียกเก็บ)|ไม่เก็บ|ไม่มีค่า(?:ใช้จ่าย|สมัคร|ธรรมเนียม)|ไม่ต้อง(?:วางเงิน|จ่าย|ชำระ)|ประกาศเตือน|เตือน|อย่า(?:บอก|โอน|ให้|เปิดเผย)|ไม่รับประกัน|ไม่ได้รับประกัน|ผลการดำเนินงานในอดีต|ผลตอบแทนในอดีต|ไม่มีค่าใช้จ่าย",
    ),
}
# Scripts written without sentence marks (Thai) are matched over the whole message.
_MESSAGE_SCOPE = {"th"}
_NAMES = {"es": "Spanish", "fr": "French", "pt": "Portuguese", "de": "German", "vi": "Vietnamese", "tl": "Tagalog", "hi": "Hindi", "ar": "Arabic", "th": "Thai"}


def _f(pattern: str, lang: str = "") -> str:
    # The engine runs NFKC over the message before matching (it splits the Thai vowel U+0E33 in two and decomposes the Devanagari
    # nukta letters), so the same must happen to the patterns or those words silently never match.
    folded = fold_for_matching(unicodedata.normalize("NFKC", pattern))
    return fold_german(folded) if lang == "de" else folded


def _build(lang: str, L: dict[str, str]) -> list[Rule]:
    sc = "message" if lang in _MESSAGE_SCOPE else "sentence"
    g = {k: _f(v, lang) for k, v in L.items()}
    name = _NAMES[lang]
    amt, pct, negamt, gain = _f(AMT, lang), _f(PCT, lang), _f(NEGAMT, lang), _f(GAIN, lang)
    rules: list[Rule] = []

    def C(*parts: str, scope: str = sc) -> str:
        return conj(*parts, scope=scope)

    def add(suffix, category, title, sev, weight, build, why, action):
        """`build` returns the pattern; a language with no vocabulary for one of its parts simply has no such rule."""
        try:
            pattern = build()
        except KeyError:
            return
        rules.append(Rule(f"{lang}_{suffix}", category, f"{title} ({name} wording)", sev, weight, pattern, why, action, fold=True))

    add("job_fee", "Advance-fee job scam", "Payment demanded to get or start a job", "critical", 38, lambda: C(g["pay"], g["fee"], g["job"], amt),
        "A real employer does not charge a candidate for an offer, a contract, training or a work permit; promising to refund it later is part of the lure.", A_JOB)
    # The "balance" a task scam shows is either a word (negative balance) or a minus sign in front of an amount ("-142 €").
    add("task_topup", "Paid-task scam", "Negative balance and a top-up demanded to unlock tasks", "critical", 40,
        lambda: C(f"{g['neg_bal']}|{negamt}", g["topup"], f"{g['unlock']}|{g['withdraw']}|{g['task']}"),
        "Task scams show a fictitious negative balance to pressure the victim into adding more money.", A_PAY)
    add("task_deposit", "Paid-task scam", "A deposit demanded to activate or unlock the task account", "critical", 40, lambda: C(g["topup"], g["task"], g["activate"], amt),
        "Task scams charge a deposit to 'activate' the account or the next task, then a bigger one to release the earnings.", A_PAY)
    add("mail_password", "Credential phishing", "Asked to log in with the password of your email account", "critical", 36, lambda: C(g["mailpass"]),
        "Fake employers send new hires to an 'onboarding portal' and ask for their email password; no employer needs the password of your email account, and with it the scammer can reset every other account you own.",
        "Do not enter it. Reach the company through its own website, and change your email password if you already did.")
    # A deposit that will supposedly be returned, in a message about tasks, commissions, withdrawing or verifying: the lure in both the
    # part-time task scam ("deposit 200 and we return it with the profit") and the fake exchange-support 'verification deposit'.
    add("refund_lure", "Advance-fee scam", "A deposit that will be returned, to unlock tasks, earnings or an account", "high", 25,
        lambda: C(g["pay"], amt, g["refund"], f"{g['withdraw']}|{g['task']}|{g['unlockfunds']}|{g['activate']}|{g['verify']}"),
        "Promising that the deposit comes straight back, with profit, is how a scam gets the first payment.", A_PAY)
    add("guaranteed", "Investment scam", "Guaranteed returns or no risk", "critical", 39, lambda: C(g["guar"], g["ctx"]),
        "All investments carry risk; guaranteed or risk-free returns are a classic warning.", A_INV)
    add("extreme_return", "Investment scam", "An extreme return per day or week", "critical", 34, lambda: C(pct, g["perday"], g["ctx"]),
        "Returns of several percent a day or a week conflict with any ordinary risk-return relationship; romance and 'my uncle taught me a platform' scams lead with them.", A_INV)
    add("withdraw_fee", "Advance-fee investment scam", "Tax or fee demanded before funds are withdrawn or released", "critical", 42,
        lambda: C(f"{g['withdraw']}|{g['unlockfunds']}", g["wd_fee"], g["pay"], f"{amt}|{pct}"),
        "Fraudulent platforms, and people posing as regulators, invent taxes and fees before a supposed release of funds.", A_PAY)
    add("mule", "Money-mule recruitment", "Asked to receive money or parcels and pass them on", "critical", 46,
        lambda: alt(*([C(g["recv"], g["fwd"])] if "recv" in g and "fwd" in g else []) + ([C(g["parcel"], g["reship"])] if "parcel" in g and "reship" in g else [])),
        "Moving third-party funds or goods can make you an intermediary for fraud or money laundering.", A_PAY)
    # The cheque is named in one sentence and the supplier in the next, so this one reads the whole message.
    add("cheque", "Fake-cheque job scam", "A cheque is sent to buy equipment from a named supplier", "critical", 40, lambda: C(g["cheque"], g["buy"], g["equip"], scope="message"),
        "A cheque can look available before it bounces; the buyer is left liable and the equipment money has gone to the scammer's supplier.", A_PAY)
    add("sensitive", "Identity harvesting", "Identity document, bank details or a one-time code requested", "critical", 35,
        lambda: alt(C(g["send"], g["doc"]), C(g["send"], g["otp"], g["acct"])),
        "Early requests for identity documents, account numbers or codes enable takeover and identity theft.", "Do not share them. Contact the organization through an independently verified channel.")
    add("recovery", "Recovery scam", "Lost funds can be recovered if you pay first", "critical", 40, lambda: C(g["lost"], g["recover"], g["pay"], scope="message"),
        "People who have already been scammed are targeted again with an offer to recover the money for a fee.", A_PAY)
    add("loan_fee", "Advance-fee scam", "A deposit or fee is demanded before a loan, grant or prize is released", "critical", 42, lambda: C(g["loan"], g["release"], g["pay"], amt, scope="message"),
        "Loans, grants and prizes that must be paid for before they are released are a standard advance-fee scam.", A_PAY)
    add("new_account", "Payment redirection", "Payment moved to a new account, old details no longer valid", "critical", 40, lambda: C(g["newacct"], g["old"], g["pay"], scope="message"),
        "An adviser or provider changing where you must pay, by message, is the standard way payments are diverted.", A_PAY)
    add("wallet", "Crypto wallet drainer", "Asked to connect a wallet and approve spending", "critical", 44, lambda: C(g["wallet"], g["approve"]),
        "Approving a token allowance lets the other party move funds out of the wallet at any time.", "Do not connect or approve. Revoke any existing approvals from a wallet tool you trust.")
    add("pump", "Pump-and-dump", "A signal group pushing a coin to buy now", "critical", 39, lambda: C(g["pump"], f"{g['guar']}|{gain}", scope="message"),
        "Members buy so the organisers can sell into the rise.", A_INV)
    return rules


LANGUAGE_RULES: tuple[Rule, ...] = tuple(rule for lang, lex in LEX.items() for rule in _build(lang, lex))
LANGUAGE_RULE_IDS: frozenset[str] = frozenset(r.id for r in LANGUAGE_RULES)

# Spanish, French and Portuguese share words ("garanti...", "nunca/jamais"), so a rule for one fires on the others and must
# recognise the others' warnings; hence the guard for a Latin-script rule is the cues of all Latin-script languages together.
_LATIN = ("es", "fr", "pt", "de", "vi", "tl")
_WARN_LATIN = re.compile("|".join(f"(?:{_f(LEX[lang]['warn'], lang)})" for lang in _LATIN), re.I)
_WARN = {lang: (_WARN_LATIN if lang in _LATIN else re.compile(_f(lex["warn"], lang), re.I)) for lang, lex in LEX.items()}
_WARN_ANY = re.compile("|".join(f"(?:{_f(lex['warn'], lang)})" for lang, lex in LEX.items()), re.I)


def sentence_warns_in_any_language(sentence: str) -> bool:
    """For the older English/Chinese/Malay/Tamil rules: does this sentence negate or report the scam in any of the nine languages?
    (An English rule firing on a Tagalog fraud warning that quotes "guaranteed returns".)"""
    return bool(_WARN_ANY.search(fold_for_matching(unicodedata.normalize("NFKC", sentence))))


# A language's rules apply only to a message written in that language. Thai and Tagalog messages mix English words in ("guaranteed",
# "wallet", "approve"), so those words are in their vocabulary, and English text would otherwise match them. Non-Latin scripts need
# the script; the Latin-script languages need two of their own function words.
_MARKERS = {
    "es": (r"\b(?:el|los|las|del|que|para|por|con|una|tu|su|debes?|esta|este|sin|pero|como|desde|tienes|hola)\b", 2),
    "fr": (r"\b(?:le|les|des|du|une|est|vous|votre|vos|pour|avec|sans|dans|que|qui|nous|cette|aux|sur|par)\b", 2),
    "pt": (r"\b(?:voce|seu|sua|seus|suas|para|sem|que|nao|uma|dos|das|pela|pelo|tem|foi|ser|ola|pra|pro|aos|nos|nas|hoje|entra|onde|ainda|vc|vcs|voces|tambem|muito|ganhe)\b", 2),
    "de": (r"\b(?:der|die|das|und|sie|ihr|ihre|ihren|ist|nicht|fur|mit|auf|ein|eine|wir|bitte|kein|keine|sind|werden)\b", 2),
    "vi": (r"\b(?:cua|cac|ban|cho|khong|duoc|toi|minh|voi|nay|mot|nhung|vui\s+long|quy\s+khach|cam\s+on|nhe|nha|anh|chi|chuc\s+mung|cong\s+ty|luong|nhan|sau|thang|tai|va|se|da|de)\b", 2),
    "tl": (r"\b(?:ang|ng|mga|sa|ako|mo|po|kami|ka|ay|lang|yung|nang|kung|dito|ito|niyo|ninyo|naman|muna|ba|kada)\b", 2),
    "hi": (r"[ऀ-ॿ]", 1),
    "ar": (r"[؀-ۿ]", 1),
    "th": (r"[฀-๿]", 1),
}
_MARKER_RX = {lang: (re.compile(_f(rx, lang), re.I), need) for lang, (rx, need) in _MARKERS.items()}


def language_applies(rule_id: str, text: str) -> bool:
    """Is the message written in the language this rule is for? (`text` is the folded message.)"""
    rx, need = _MARKER_RX[rule_id.split("_", 1)[0]]
    return len(rx.findall(text)) >= need


def language_warning(rule_id: str, text: str, match: re.Match[str]) -> bool:
    """True when the sentence (or, for message-wide rules, the message) the rule matched in negates or reports the scam."""
    return bool(_WARN[rule_id.split("_", 1)[0]].search(match.group(0)))
