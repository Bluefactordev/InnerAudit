#!/usr/bin/env python3
"""InnerAudit - Flask web interface for the code audit system."""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from audit_engine import AuditEngine, ConfigManager

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "audit_config.json"
BEST_PRACTICES_PATH = BASE_DIR / "audit_best_practices.md"
LOG_PATH = BASE_DIR / "inneraudit.log"
DEFAULT_REPORT_DIR = BASE_DIR / "audit_reports"

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.config["SECRET_KEY"] = os.getenv(
    "INNERAUDIT_SECRET_KEY",
    "inneraudit-dev-secret-change-me",
)

config_manager = ConfigManager(CONFIG_PATH)
audit_engine = AuditEngine(config_manager)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("InnerAudit")


def _get_json_payload() -> Dict[str, Any]:
    """Return a JSON request payload or an empty dict."""
    return request.get_json(silent=True) or {}


def _normalize_patterns(values: Any) -> list[str]:
    """Normalize include/exclude patterns coming from the UI."""
    if not isinstance(values, list):
        return []
    normalized = []
    for value in values:
        if isinstance(value, str):
            pattern = value.strip()
            if pattern:
                normalized.append(pattern)
    return normalized


def _get_report_dir() -> Path:
    """Resolve the report directory relative to this app."""
    report_dir = Path(config_manager.get_output_config().get("report_dir", "audit_reports"))
    if not report_dir.is_absolute():
        report_dir = BASE_DIR / report_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def _resolve_report_file(filename: str) -> Optional[Path]:
    """Return a safe report path or None if the filename is invalid."""
    safe_name = secure_filename(filename)
    if safe_name != filename or not safe_name.endswith(".json"):
        return None

    report_dir = _get_report_dir().resolve()
    report_file = (report_dir / safe_name).resolve()

    try:
        report_file.relative_to(report_dir)
    except ValueError:
        return None

    return report_file


# ============================================================================
# Routes - Main Pages
# ============================================================================

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/audit')
def audit_page():
    """Audit configuration and execution page"""
    return render_template('audit.html')


@app.route('/reports')
def reports_page():
    """Reports listing page"""
    return render_template('reports.html')


# ============================================================================
# API Routes - Configuration
# ============================================================================

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        return jsonify({
            'success': True,
            'config': {
                'models': [
                    {
                        'id': m.id,
                        'name': m.name,
                        'type': m.type,
                        'api_base': m.api_base
                    }
                    for m in config_manager.get_models()
                ],
                'platforms': list(config_manager.config.get('platforms', {}).keys()),
                'file_filtering': config_manager.get_file_filtering()
            }
        })
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/platform/<platform_name>', methods=['GET'])
def get_platform_info(platform_name):
    """Get platform analysis types"""
    try:
        platform = config_manager.get_platform(platform_name)
        if not platform:
            return jsonify({'success': False, 'error': 'Platform not found'}), 404
        
        return jsonify({
            'success': True,
            'platform': {
                'name': platform.name,
                'file_extensions': platform.file_extensions,
                'analysis_types': {
                    key: {
                        'name': atype.name,
                        'scope': atype.scope
                    }
                    for key, atype in platform.analysis_types.items()
                }
            }
        })
    except Exception as e:
        logger.error(f"Error getting platform info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/best-practices', methods=['GET'])
def get_best_practices():
    """Get best practices content"""
    try:
        if BEST_PRACTICES_PATH.exists():
            with open(BEST_PRACTICES_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({'success': True, 'content': content})
        else:
            return jsonify({'success': False, 'error': 'Best practices file not found'}), 404
    except Exception as e:
        logger.error(f"Error getting best practices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/best-practices', methods=['POST'])
def save_best_practices():
    """Save best practices content"""
    try:
        data = _get_json_payload()
        content = data.get('content', '')

        with open(BEST_PRACTICES_PATH, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return jsonify({'success': True, 'message': 'Best practices saved'})
    except Exception as e:
        logger.error(f"Error saving best practices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# API Routes - File Filtering
# ============================================================================

@app.route('/api/file-filtering', methods=['GET'])
def get_file_filtering():
    """Get file filtering configuration"""
    try:
        filtering = config_manager.get_file_filtering()
        return jsonify({'success': True, 'filtering': filtering})
    except Exception as e:
        logger.error(f"Error getting file filtering: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/file-filtering', methods=['POST'])
def save_file_filtering():
    """Save file filtering configuration"""
    try:
        data = _get_json_payload()

        with open(config_manager.config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)

        default_behavior = data.get('default_behavior', 'include_all')
        if default_behavior not in {'include_all', 'include_only', 'exclude_only'}:
            default_behavior = 'include_all'

        config_data['file_filtering'] = {
            'description': 'Configure which directories/files to include or exclude from audit',
            'include_patterns': _normalize_patterns(data.get('include_patterns', [])),
            'exclude_patterns': _normalize_patterns(data.get('exclude_patterns', [])),
            'default_behavior': default_behavior
        }

        with open(config_manager.config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2)

        config_manager._load_config()
        
        return jsonify({'success': True, 'message': 'File filtering saved'})
    except Exception as e:
        logger.error(f"Error saving file filtering: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# API Routes - Audit Execution
# ============================================================================

@app.route('/api/audit/run', methods=['POST'])
def run_audit():
    """Run audit on a project"""
    try:
        data = _get_json_payload()

        raw_project_path = data.get('project_path')
        model_id = data.get('model_id')
        platform_name = data.get('platform')
        analysis_types = data.get('analysis_types', [])
        use_linting = data.get('use_linting', True)

        if not all([raw_project_path, model_id, platform_name, analysis_types]):
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            }), 400

        project_path = Path(str(raw_project_path)).expanduser().resolve()
        if not project_path.is_dir():
            return jsonify({
                'success': False,
                'error': f'Project path does not exist or is not a directory: {project_path}'
            }), 400

        model = config_manager.get_model_by_id(model_id)
        platform = config_manager.get_platform(platform_name)

        if not model:
            return jsonify({'success': False, 'error': 'Model not found'}), 404
        if not platform:
            return jsonify({'success': False, 'error': 'Platform not found'}), 404

        logger.info(f"Starting audit on {project_path}")
        results = audit_engine.run_audit(
            project_path=str(project_path),
            model=model,
            platform=platform,
            analysis_types=analysis_types,
            use_linting=use_linting
        )

        report_file = audit_engine.generate_report(results, model, platform, str(project_path))
        
        return jsonify({
            'success': True,
            'message': 'Audit completed',
            'report_file': report_file.name,
            'stats': {
                'total_files': len(set(r.file_path for r in results)),
                'total_findings': sum(len(r.findings) for r in results),
                'critical_findings': sum(
                    1 for r in results
                    for f in r.findings
                    if f.get('severity') in ['critical', 'high']
                )
            }
        })
    except Exception as e:
        logger.error(f"Error running audit: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/audit/test-model', methods=['POST'])
def test_model():
    """Test model connection"""
    try:
        data = _get_json_payload()
        model_id = data.get('model_id')
        
        if not model_id:
            return jsonify({'success': False, 'error': 'Missing model_id'}), 400
        
        model = config_manager.get_model_by_id(model_id)
        if not model:
            return jsonify({'success': False, 'error': 'Model not found'}), 404
        
        # Test connection
        success, message = audit_engine.test_model_connection(model)
        
        return jsonify({
            'success': success,
            'message': message
        })
    except Exception as e:
        logger.error(f"Error testing model: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# API Routes - Reports
# ============================================================================

@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all audit reports"""
    try:
        report_dir = _get_report_dir()
        if not report_dir.exists():
            return jsonify({'success': True, 'reports': []})
        
        reports = []
        for report_file in sorted(report_dir.glob('*.json'), reverse=True):
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                reports.append({
                    'filename': report_file.name,
                    'timestamp': report_data['metadata']['timestamp'],
                    'project_path': report_data['metadata']['project_path'],
                    'platform': report_data['metadata']['platform'],
                    'total_files': report_data['metadata']['total_files'],
                    'total_findings': report_data['metadata']['total_findings'],
                    'critical_findings': report_data['metadata']['critical_findings']
                })
            except Exception as e:
                logger.warning(f"Error reading report {report_file}: {e}")
                continue
        
        return jsonify({'success': True, 'reports': reports})
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/<filename>', methods=['GET'])
def get_report(filename):
    """Get a specific report"""
    try:
        report_file = _resolve_report_file(filename)

        if report_file is None or not report_file.exists():
            return jsonify({'success': False, 'error': 'Report not found'}), 404

        with open(report_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return jsonify({'success': True, 'report': report_data})
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Static Files
# ============================================================================

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory(BASE_DIR / 'static', filename)


# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    DEFAULT_REPORT_DIR.mkdir(exist_ok=True)
    (BASE_DIR / 'templates').mkdir(exist_ok=True)
    (BASE_DIR / 'static').mkdir(exist_ok=True)

    app.run(
        host=os.getenv('INNERAUDIT_HOST', '0.0.0.0'),
        port=int(os.getenv('INNERAUDIT_PORT', '5100')),
        debug=os.getenv('INNERAUDIT_DEBUG', '').lower() in {'1', 'true', 'yes'},
    )
