"""
Flask Application for Professional Security Scanner Web Interface

This provides a modern, real-time web interface for security scanning with:
- WebSocket support for live scan updates
- Interactive dashboards
- Scan queue management
- Report generation and export
"""

import os
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Import scanner components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from website_security_scanner.main import LowCodeSecurityScanner
from website_security_scanner.enhanced_report_generator import EnhancedReportGenerator
from website_security_scanner.result_transformer import transform_results_for_professional_report
from website_security_scanner.verifier import VulnerabilityVerifier

# Global configuration
UPLOAD_FOLDER = Path('data/uploads')
REPORTS_FOLDER = Path('data/reports')
SCANS_FOLDER = Path('data/scans')

# Create directories
for folder in [UPLOAD_FOLDER, REPORTS_FOLDER, SCANS_FOLDER]:
    folder.mkdir(parents=True, exist_ok=True)

# Initialize Flask app
socketio = None


def create_app(config=None):
    """Create and configure the Flask application."""
    global socketio
    
    app = Flask(__name__, 
                template_folder=str(Path(__file__).parent / 'templates'),
                static_folder=str(Path(__file__).parent / 'static'))
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
    app.config['REPORTS_FOLDER'] = str(REPORTS_FOLDER)
    app.config['SCANS_FOLDER'] = str(SCANS_FOLDER)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    if config:
        app.config.update(config)
    
    # Enable CORS
    CORS(app)
    
    # Initialize SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    # Initialize scanner components
    app.scanner = LowCodeSecurityScanner()
    app.report_generator = EnhancedReportGenerator()
    app.verifier = VulnerabilityVerifier(app.scanner.session)
    
    # Scan queue and history
    app.scan_queue = []
    app.scan_history = []
    app.active_scans = {}
    
    # Register routes
    register_routes(app)
    register_socketio_events(app, socketio)
    
    return app


def register_routes(app):
    """Register all HTTP routes."""
    
    @app.route('/')
    def index():
        """Main dashboard page."""
        return render_template('index.html')
    
    @app.route('/scan')
    def scan_page():
        """Scan configuration page."""
        return render_template('scan.html')
    
    @app.route('/history')
    def history_page():
        """Scan history page."""
        return render_template('history.html')
    
    @app.route('/reports')
    def reports_page():
        """Reports management page."""
        return render_template('reports.html')
    
    @app.route('/api/scan/single', methods=['POST'])
    def api_scan_single():
        """Start a single URL scan."""
        data = request.get_json()
        url = data.get('url')
        verify_vulns = data.get('verify_vulnerabilities', False)
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(app.scan_queue)}"
        
        scan_job = {
            'id': scan_id,
            'url': url,
            'verify': verify_vulns,
            'status': 'queued',
            'created_at': datetime.now().isoformat(),
            'progress': 0
        }
        
        app.scan_queue.append(scan_job)
        
        # Start scan in background thread
        thread = threading.Thread(target=execute_scan, args=(app, socketio, scan_id))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan queued successfully'
        })
    
    @app.route('/api/scan/batch', methods=['POST'])
    def api_scan_batch():
        """Start a batch scan of multiple URLs."""
        data = request.get_json()
        urls = data.get('urls', [])
        verify_vulns = data.get('verify_vulnerabilities', False)
        
        if not urls:
            return jsonify({'error': 'URLs list is required'}), 400
        
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_ids = []
        
        for i, url in enumerate(urls):
            scan_id = f"{batch_id}_{i}"
            scan_job = {
                'id': scan_id,
                'batch_id': batch_id,
                'url': url,
                'verify': verify_vulns,
                'status': 'queued',
                'created_at': datetime.now().isoformat(),
                'progress': 0
            }
            app.scan_queue.append(scan_job)
            scan_ids.append(scan_id)
        
        # Start batch scan in background
        thread = threading.Thread(target=execute_batch_scan, args=(app, socketio, scan_ids))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'scan_ids': scan_ids,
            'message': f'Batch scan of {len(urls)} URLs queued successfully'
        })
    
    @app.route('/api/scan/<scan_id>/status', methods=['GET'])
    def api_scan_status(scan_id):
        """Get status of a specific scan."""
        # Check active scans
        if scan_id in app.active_scans:
            return jsonify(app.active_scans[scan_id])
        
        # Check queue
        for scan in app.scan_queue:
            if scan['id'] == scan_id:
                return jsonify(scan)
        
        # Check history
        for scan in app.scan_history:
            if scan['id'] == scan_id:
                return jsonify(scan)
        
        return jsonify({'error': 'Scan not found'}), 404
    
    @app.route('/api/scan/<scan_id>/results', methods=['GET'])
    def api_scan_results(scan_id):
        """Get results of a completed scan."""
        result_file = Path(app.config['SCANS_FOLDER']) / f"{scan_id}.json"
        
        if result_file.exists():
            with open(result_file, 'r') as f:
                results = json.load(f)
            return jsonify(results)
        
        return jsonify({'error': 'Results not found'}), 404
    
    @app.route('/api/scan/<scan_id>/report', methods=['GET'])
    def api_scan_report(scan_id):
        """Generate and download HTML report for a scan."""
        result_file = Path(app.config['SCANS_FOLDER']) / f"{scan_id}.json"
        
        if not result_file.exists():
            return jsonify({'error': 'Scan results not found'}), 404
        
        with open(result_file, 'r') as f:
            results = json.load(f)
        
        # Generate report
        report_path = Path(app.config['REPORTS_FOLDER']) / f"{scan_id}.html"
        enhanced_results = transform_results_for_professional_report(results)
        app.report_generator.generate_report(enhanced_results, str(report_path))
        
        return send_file(str(report_path), as_attachment=True, 
                        download_name=f"security_report_{scan_id}.html")
    
    @app.route('/api/history', methods=['GET'])
    def api_scan_history():
        """Get scan history."""
        return jsonify({
            'history': app.scan_history[-50:],  # Last 50 scans
            'total': len(app.scan_history)
        })
    
    @app.route('/api/queue', methods=['GET'])
    def api_scan_queue():
        """Get current scan queue."""
        return jsonify({
            'queue': app.scan_queue,
            'active': list(app.active_scans.values())
        })
    
    @app.route('/api/stats', methods=['GET'])
    def api_stats():
        """Get scanner statistics."""
        total_scans = len(app.scan_history)
        completed = len([s for s in app.scan_history if s.get('status') == 'completed'])
        failed = len([s for s in app.scan_history if s.get('status') == 'failed'])
        
        total_vulns = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for scan in app.scan_history:
            vulns = scan.get('vulnerability_count', 0)
            total_vulns += vulns
            
            # Count by severity if available
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                severity_counts[sev] += scan.get(f'{sev}_count', 0)
        
        return jsonify({
            'total_scans': total_scans,
            'completed_scans': completed,
            'failed_scans': failed,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'queue_length': len(app.scan_queue),
            'active_scans': len(app.active_scans)
        })


def register_socketio_events(app, socketio):
    """Register WebSocket event handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        emit('connected', {'message': 'Connected to security scanner'})
    
    @socketio.on('subscribe_scan')
    def handle_subscribe(data):
        """Subscribe to scan updates."""
        scan_id = data.get('scan_id')
        if scan_id:
            # Client will receive updates for this scan
            emit('subscribed', {'scan_id': scan_id})
    
    @socketio.on('request_stats')
    def handle_stats_request():
        """Send current statistics."""
        stats = {
            'total_scans': len(app.scan_history),
            'queue_length': len(app.scan_queue),
            'active_scans': len(app.active_scans)
        }
        emit('stats_update', stats)


def execute_scan(app, socketio, scan_id):
    """Execute a single scan in background thread."""
    # Find scan job
    scan_job = None
    for scan in app.scan_queue:
        if scan['id'] == scan_id:
            scan_job = scan
            break
    
    if not scan_job:
        return
    
    # Move to active scans
    app.scan_queue.remove(scan_job)
    scan_job['status'] = 'running'
    scan_job['started_at'] = datetime.now().isoformat()
    app.active_scans[scan_id] = scan_job
    
    # Emit status update
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'status': 'running',
        'progress': 0,
        'message': 'Starting scan...'
    })
    
    try:
        url = scan_job['url']
        verify = scan_job.get('verify', False)
        
        # Update progress
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 10,
            'message': 'Identifying platform...'
        })
        
        # Perform scan
        results = app.scanner.scan_target(url)
        
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 60,
            'message': 'Analyzing vulnerabilities...'
        })
        
        # Verify vulnerabilities if requested
        if verify and results.get('vulnerabilities'):
            socketio.emit('scan_update', {
                'scan_id': scan_id,
                'progress': 70,
                'message': 'Verifying vulnerabilities...'
            })
            
            verified_count = 0
            for i, vuln in enumerate(results['vulnerabilities']):
                verification = app.verifier.verify_vulnerability(vuln)
                vuln['verification'] = verification
                if verification.get('verified'):
                    verified_count += 1
                
                progress = 70 + (i / len(results['vulnerabilities'])) * 20
                socketio.emit('scan_update', {
                    'scan_id': scan_id,
                    'progress': int(progress),
                    'message': f'Verified {verified_count} vulnerabilities...'
                })
        
        # Save results
        result_file = Path(app.config['SCANS_FOLDER']) / f"{scan_id}.json"
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Count vulnerabilities by severity
        vulns = results.get('vulnerabilities', [])
        severity_counts = {}
        for vuln in vulns:
            sev = vuln.get('severity', 'info').lower()
            severity_counts[f'{sev}_count'] = severity_counts.get(f'{sev}_count', 0) + 1
        
        # Update scan job
        scan_job['status'] = 'completed'
        scan_job['completed_at'] = datetime.now().isoformat()
        scan_job['progress'] = 100
        scan_job['vulnerability_count'] = len(vulns)
        scan_job.update(severity_counts)
        scan_job['platform'] = results.get('platform_type', 'unknown')
        
        # Move to history
        app.active_scans.pop(scan_id)
        app.scan_history.append(scan_job)
        
        # Emit completion
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'status': 'completed',
            'progress': 100,
            'message': 'Scan completed successfully',
            'vulnerability_count': len(vulns),
            'results': results
        })
        
    except Exception as e:
        # Handle error
        scan_job['status'] = 'failed'
        scan_job['error'] = str(e)
        scan_job['completed_at'] = datetime.now().isoformat()
        
        app.active_scans.pop(scan_id, None)
        app.scan_history.append(scan_job)
        
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e),
            'message': f'Scan failed: {str(e)}'
        })


def execute_batch_scan(app, socketio, scan_ids):
    """Execute multiple scans sequentially."""
    for scan_id in scan_ids:
        execute_scan(app, socketio, scan_id)
        # Small delay between scans
        import time
        time.sleep(2)


if __name__ == '__main__':
    app = create_app()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
