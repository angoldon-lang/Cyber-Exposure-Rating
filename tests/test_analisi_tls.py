"""testssl.sh produceva zero evidenze a ogni scansione.

Non per un host pulito: per la forma del suo output. Con `--jsonfile-pretty`
testssl mette gli host sotto `scanResult` e i rilievi in una lista per
sezione dentro l'host; il parser iterava `scanResult`, i cui elementi sono
host e non hanno alcun campo `id`. Nessun rilievo veniva riconosciuto, mentre
lo strumento consumava la maggior parte del tempo dell'analisi.

La fixture conserva la struttura di un'esecuzione reale di testssl.sh 3.2.4
(`--jsonfile-pretty --quiet --color 0 --severity LOW --sneaky`); i rilievi
sono stati sostituiti con i casi che il parser deve saper leggere.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from adapters.testssl_adapter import TestSSLAdapter, giorni_alla_scadenza, rilievi_testssl

pytestmark = pytest.mark.security

FIXTURE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "testssl_pretty.json")
                     .read_text(encoding="utf-8"))


def test_i_rilievi_annidati_vengono_trovati():
    identificatori = {r["id"] for r in rilievi_testssl(FIXTURE)}

    assert "TLS1_1" in identificatori, "le sezioni dell'host non vengono aperte"
    assert "cipherlist_3DES_IDEA" in identificatori
    assert any(i.startswith("cert_expirationStatus") for i in identificatori)


def test_la_forma_piatta_resta_leggibile():
    """`--jsonfile` scrive una lista piatta: il parser non deve dipendere
    dall'opzione scelta."""
    assert rilievi_testssl([{"id": "TLS1", "finding": "offered"}]) == [
        {"id": "TLS1", "finding": "offered"}]


def test_dalla_fixture_nascono_evidenze(adapter_context):
    strumento = TestSSLAdapter(adapter_context)
    evidenze = strumento._analyse_testssl("www.example.it", FIXTURE)
    tipi = {e.finding_type for e in evidenze}

    assert evidenze, "un output reale di testssl deve produrre evidenze"
    assert "tls_legacy_protocol" in tipi
    assert "tls_weak_cipher" in tipi
    assert "tls_certificate_expiring" in tipi
    assert "tls_certificate_hostname_mismatch" in tipi


def test_il_postfix_del_secondo_certificato_non_nasconde_il_rilievo(adapter_context):
    """Con RSA ed ECDSA insieme testssl scrive `cert_expirationStatus
    <hostCert#2>`: il confronto per uguaglianza falliva sugli host meglio
    configurati."""
    strumento = TestSSLAdapter(adapter_context)
    evidenze = strumento._analyse_testssl("www.example.it", FIXTURE)

    scadenza = [e for e in evidenze if e.finding_type == "tls_certificate_expiring"]
    assert len(scadenza) == 1
    assert scadenza[0].detail == "25"


@pytest.mark.parametrize(("testo", "atteso"), [
    ("expired", -1),
    ("89 >= 60 days", 89),
    # Il 30 e' la soglia d'allarme, non il residuo: leggerlo al suo posto fa
    # credere che il certificato duri piu' di quanto duri.
    ("expires < 30 days (25)", 25),
    ("", None),
])
def test_giorni_alla_scadenza(testo, atteso):
    assert giorni_alla_scadenza(testo) == atteso


def test_output_interrotto_non_produce_evidenze_inventate():
    """Interrotto, testssl scrive JSON malformato; a monte viene scartato.
    Qui si verifica solo che una struttura senza rilievi non generi nulla."""
    assert rilievi_testssl({"scanResult": [], "scanTime": "Scan interrupted"}) == []
    assert rilievi_testssl(None) == []


def test_i_nomi_che_non_risolvono_non_vengono_provati(adapter_context, monkeypatch):
    """Dai log di Certificate Transparency arrivano nomi di host dismessi.

    testssl ci esce con codice 247 dopo aver comunque atteso il DNS: nel
    registro dell'ultima scansione erano la maggior parte dei fallimenti, e
    facevano risultare non verificato un TLS che non esiste.
    """
    from adapters import testssl_adapter

    monkeypatch.setattr(testssl_adapter, "_risolve", lambda host: False)
    strumento = testssl_adapter.TestSSLAdapter(adapter_context)
    monkeypatch.setattr(strumento.context.scope_guard, "filter_targets",
                        lambda valori, tipo: ["dismesso.example.it"])
    monkeypatch.setattr(testssl_adapter, "run_command", _run_command_vietato)

    esito = strumento.execute()

    assert esito.status.value == "skipped"
    assert "risolve" in (esito.error_message or "")


def _run_command_vietato(*args, **kwargs):  # noqa: ANN002, ANN003
    raise AssertionError("testssl non deve essere eseguito su un nome inesistente")
