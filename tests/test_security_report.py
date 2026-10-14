import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel

from core.security_report import build_security_report, write_json_report, write_pdf_report
from core.purple_team import build_json_report
from gui.main_window import MainWindow


def _application():
    return QApplication.instance() or QApplication([])


def test_report_branding_and_json_output(tmp_path):
    report = build_security_report({"domain": "example.test", "users": []})
    output = tmp_path / "ad-vigil-report.json"

    write_json_report(report, output)

    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["cover"]["tool"] == "AD Vigil"
    assert saved["cover"]["project_title"] == "AD Vigil — Active Directory Security Assessment & Purple Team Platform"
    assert saved["cover"]["tagline"] == "Find the weakness. Detect the activity. Strengthen the domain."
    combined = build_json_report({}, [], [], [], [])
    assert combined["product"]["name"] == "AD Vigil"
    assert combined["product"]["tagline"] == saved["cover"]["tagline"]


def test_pdf_output_is_generated_without_extra_pdf_dependency(tmp_path):
    _application()
    report = build_security_report({"domain": "example.test", "users": []})
    output = tmp_path / "ad-vigil-report.pdf"

    write_pdf_report(report, output)

    assert output.read_bytes().startswith(b"%PDF-")
    assert output.stat().st_size > 1_000


def test_application_shell_uses_ad_vigil_branding():
    _application()
    window = MainWindow()
    assert window.windowTitle() == "AD Vigil — Active Directory Security Assessment & Purple Team Platform"
    assert window.findChild(QLabel, "header").text() == "AD VIGIL"
    assert window.findChild(QLabel, "tagline").text() == "Find the weakness. Detect the activity. Strengthen the domain."
    window.close()
