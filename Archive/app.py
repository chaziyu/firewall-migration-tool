import os
import shutil
import subprocess
import zipfile
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="FortiGate to Palo Alto Converter API")

# Ensure static directory exists
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Project paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_DIR = os.path.join(BASE_DIR, "csv_output")
XML_FILE = os.path.join(BASE_DIR, "palo_alto_converted.xml")
EXTRACTOR_SCRIPT = os.path.join(BASE_DIR, "src", "extractor.py")
CONVERTER_SCRIPT = os.path.join(BASE_DIR, "src", "converter_core.py")
PA_EXTRACTOR_SCRIPT = os.path.join(BASE_DIR, "src", "pa_extractor.py")
FG_CONVERTER_SCRIPT = os.path.join(BASE_DIR, "src", "fg_converter_core.py")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
TEMP_ZIP = os.path.join(BASE_DIR, "export.zip")
FG_CONF_FILE = os.path.join(BASE_DIR, "fortigate_converted.conf")

os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open(os.path.join("static", "index.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/convert")
async def convert_config(
    file: UploadFile = File(...),
    direction: str = Form(...),
    export_type: str = Form(...)
):
    if direction == "fg_to_pa" and not file.filename.endswith(".conf"):
        raise HTTPException(status_code=400, detail="Only .conf files are supported for FortiGate to Palo Alto")
    if direction == "pa_to_fg" and not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="Only .xml files are supported for Palo Alto to FortiGate")

    # Clean up previous runs
    if os.path.exists(CSV_DIR):
        try:
            shutil.rmtree(CSV_DIR)
        except Exception as e:
            print(f"Warning: Could not remove directory {CSV_DIR}: {e}")
    if os.path.exists(XML_FILE):
        try:
            os.remove(XML_FILE)
        except Exception as e:
            print(f"Warning: Could not remove {XML_FILE}: {e}")
    if os.path.exists(FG_CONF_FILE):
        try:
            os.remove(FG_CONF_FILE)
        except Exception as e:
            print(f"Warning: Could not remove {FG_CONF_FILE}: {e}")
    if os.path.exists(TEMP_ZIP):
        try:
            os.remove(TEMP_ZIP)
        except Exception as e:
            print(f"Warning: Could not remove {TEMP_ZIP}: {e}")

    # Save uploaded file
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        if direction == "fg_to_pa":
            # Step 1: Run Extractor
            print(f"Running extractor on {file_path}...")
            extract_result = subprocess.run(
                ["python", EXTRACTOR_SCRIPT, "-f", file_path, "-o", CSV_DIR],
                capture_output=True, text=True
            )
            if extract_result.returncode != 0:
                raise HTTPException(status_code=500, detail=f"Extraction failed: {extract_result.stderr}")

            # Step 2: Run Converter
            if export_type in ["xml", "both"]:
                print("Running converter...")
                convert_result = subprocess.run(
                    ["python", CONVERTER_SCRIPT],
                    capture_output=True, text=True
                )
                if convert_result.returncode != 0:
                    raise HTTPException(status_code=500, detail=f"Conversion failed: {convert_result.stderr}")
        else:
            # direction == "pa_to_fg"
            print(f"Running PA extractor on {file_path}...")
            extract_result = subprocess.run(
                ["python", PA_EXTRACTOR_SCRIPT, "-f", file_path, "-o", CSV_DIR],
                capture_output=True, text=True
            )
            if extract_result.returncode != 0:
                raise HTTPException(status_code=500, detail=f"Extraction failed: {extract_result.stderr}")

            if export_type in ["xml", "both"]:
                print("Running FG converter...")
                convert_result = subprocess.run(
                    ["python", FG_CONVERTER_SCRIPT],
                    capture_output=True, text=True
                )
                if convert_result.returncode != 0:
                    raise HTTPException(status_code=500, detail=f"Conversion failed: {convert_result.stderr}")

        # Step 3: Package Results
        with zipfile.ZipFile(TEMP_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
            if export_type in ["csv", "both"]:
                if os.path.exists(CSV_DIR):
                    for root, _, files in os.walk(CSV_DIR):
                        for f in files:
                            file_path_zip = os.path.join(root, f)
                            arcname = os.path.relpath(file_path_zip, BASE_DIR)
                            zipf.write(file_path_zip, arcname)
            
            if export_type in ["xml", "both"]:
                if direction == "fg_to_pa" and os.path.exists(XML_FILE):
                    zipf.write(XML_FILE, "palo_alto_converted.xml")
                elif direction == "pa_to_fg" and os.path.exists(FG_CONF_FILE):
                    zipf.write(FG_CONF_FILE, "fortigate_converted.conf")

        return FileResponse(
            path=TEMP_ZIP,
            media_type="application/zip",
            filename="fortigate_to_palo_export.zip" if direction == "fg_to_pa" else "palo_to_fortigate_export.zip"
        )

    finally:
        # Clean up uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
