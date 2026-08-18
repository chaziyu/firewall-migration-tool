import os
import io
import zipfile
from flask import Flask, render_template, request, send_file, jsonify

from fg2pan.parser.fortigate_parser import parse_fortigate_config
from fg2pan.transformer.fg_to_ir import FGToIRTransformer
from fg2pan.generator.panos_xml import PANOSXMLGenerator
from fg2pan.generator.txt_report import TXTReportGenerator
from fg2pan.report.migration_report import MigrationReporter

def create_app():
    # Set static/template folders relative to this file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        static_folder=os.path.join(base_dir, 'static'),
        template_folder=os.path.join(base_dir, 'templates')
    )

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/migrate', methods=['POST'])
    def migrate():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        try:
            fg_text = file.read().decode('utf-8')
            
            # 1. Parse Config
            fg_config = parse_fortigate_config(fg_text)
            
            # 2. Transform to IR
            transformer = FGToIRTransformer(fg_config)
            ir_config = transformer.transform()
            
            # 3. Generate Artifacts
            # XML
            xml_gen = PANOSXMLGenerator()
            xml_artifacts = xml_gen.generate(ir_config)
            
            # TXT Summary
            txt_gen = TXTReportGenerator()
            txt_artifacts = txt_gen.generate(ir_config)
            
            # MD Audit Report
            reporter = MigrationReporter(ir_config)
            report_content = reporter.generate_report()
            
            # 4. Package into ZIP
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Write XML
                for art in xml_artifacts:
                    zf.writestr(art.filename, art.content)
                # Write TXT
                zf.writestr(txt_artifacts[0].filename, txt_artifacts[0].content)
                # Write MD
                zf.writestr("audit_report.md", report_content)
                
            memory_file.seek(0)
            
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name='migration_results.zip'
            )

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app
