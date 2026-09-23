import io

from openpyxl import load_workbook

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.export.excel import export_checkpoint_excel
from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input


def test_secret_bearing_source_is_redacted_from_preview_and_excel():
    secret = "checkpoint-secret-regression"
    result = extract_checkpoint_source(f'{{"objects":[{{"type":"host","name":"x","password":"{secret}"}}]}}')
    output = io.BytesIO()
    export_checkpoint_excel(result, output)
    values = " ".join(str(cell.value) for sheet in load_workbook(io.BytesIO(output.getvalue()), read_only=True).worksheets for row in sheet.iter_rows() for cell in row)
    assert secret not in str(result.config.model_dump()) + str(result.source_objects) + values


def test_gaia_secret_is_redacted_before_typed_evidence():
    secret = "gaia-secret-regression"
    bundle, _ = load_checkpoint_input(f"set user admin password {secret}\nset user admin shell /bin/bash\n")
    result = extract_checkpoint_config(bundle)
    assert secret not in str(result.config.model_dump())
    assert secret not in str(result.source_objects)
