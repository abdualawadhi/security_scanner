# Professional Web Frontend Guide

## Overview

The Low-Code Security Scanner now includes a professional web-based interface with real-time scanning capabilities, interactive dashboards, and comprehensive vulnerability management.

## Features

### 🎯 Core Features

1. **Real-Time Scan Monitoring**
   - WebSocket-based live progress updates
   - Active scan queue management
   - Progress bars and status indicators
   - Immediate notification of completed scans

2. **Interactive Dashboard**
   - Statistics overview (total scans, active scans, vulnerabilities)
   - Severity distribution charts (Chart.js visualizations)
   - Scan status breakdown
   - Recent scans at a glance

3. **Professional Scan Interface**
   - Single URL scanning
   - Batch URL scanning
   - Configurable scan options:
     - Vulnerability verification (active testing)
     - Deep scan mode
     - API endpoint discovery
   - Platform auto-detection

4. **Comprehensive History Management**
   - Filterable scan history
   - Search functionality
   - Pagination support
   - Export to HTML reports

5. **Report Generation**
   - Professional Burp Suite-style HTML reports
   - Downloadable from any completed scan
   - Detailed vulnerability information
   - Security scoring and risk levels

## Architecture

### Technology Stack

- **Backend**: Flask web framework
- **Real-time Communication**: Socket.IO (WebSocket)
- **Frontend**: Tailwind CSS, Chart.js, Font Awesome
- **Data Storage**: JSON files (scan results, history)

### Directory Structure

```
src/website_security_scanner/web/
├── __init__.py              # Web module initialization
├── app.py                   # Flask application & routes
├── run_server.py           # Server startup script
├── templates/              # HTML templates
│   ├── base.html          # Base template with navigation
│   ├── index.html         # Dashboard page
│   ├── scan.html          # Scan configuration page
│   ├── history.html       # Scan history page
│   └── reports.html       # Reports management page
└── static/                # Static assets (if needed)

data/                      # Created at runtime
├── uploads/              # Uploaded batch files
├── reports/              # Generated HTML reports
└── scans/                # Scan result JSON files
```

## Getting Started

### Installation

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Web Server**
   ```bash
   wss-web
   ```

   Or with custom options:
   ```bash
   wss-web --host 0.0.0.0 --port 8080 --debug
   ```

3. **Access the Interface**
   - Open browser to: http://localhost:5000
   - Default credentials: None required (open access in development)

### Production Deployment

For production deployment, consider:

1. **Use a Production WSGI Server**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -k eventlet 'website_security_scanner.web.app:create_app()'
   ```

2. **Enable HTTPS**
   - Use nginx or Apache as reverse proxy
   - Configure SSL certificates
   - Update Socket.IO configuration for WSS

3. **Secure Access**
   - Implement authentication (Flask-Login)
   - Add role-based access control
   - Use environment variables for secrets

4. **Database Backend** (Optional)
   - Replace JSON storage with PostgreSQL/MySQL
   - Implement proper scan archival
   - Add advanced querying capabilities

## API Endpoints

### Scan Management

#### POST /api/scan/single
Start a single URL scan.

**Request Body:**
```json
{
  "url": "https://example.bubbleapps.io",
  "verify_vulnerabilities": true
}
```

**Response:**
```json
{
  "success": true,
  "scan_id": "scan_20240130_123456_0",
  "message": "Scan queued successfully"
}
```

#### POST /api/scan/batch
Start a batch scan of multiple URLs.

**Request Body:**
```json
{
  "urls": [
    "https://app1.bubbleapps.io",
    "https://app2.outsystems.com"
  ],
  "verify_vulnerabilities": false
}
```

**Response:**
```json
{
  "success": true,
  "batch_id": "batch_20240130_123456",
  "scan_ids": ["batch_20240130_123456_0", "batch_20240130_123456_1"],
  "message": "Batch scan of 2 URLs queued successfully"
}
```

#### GET /api/scan/{scan_id}/status
Get the status of a specific scan.

**Response:**
```json
{
  "id": "scan_20240130_123456_0",
  "url": "https://example.com",
  "status": "running",
  "progress": 65,
  "created_at": "2024-01-30T12:34:56",
  "started_at": "2024-01-30T12:34:57"
}
```

#### GET /api/scan/{scan_id}/results
Get the full results of a completed scan.

**Response:** Complete scan results JSON

#### GET /api/scan/{scan_id}/report
Download the HTML report for a scan.

**Response:** HTML file download

### History & Statistics

#### GET /api/history
Get scan history.

**Response:**
```json
{
  "history": [
    {
      "id": "scan_20240130_123456_0",
      "url": "https://example.com",
      "status": "completed",
      "vulnerability_count": 5,
      "platform": "bubble",
      "created_at": "2024-01-30T12:34:56"
    }
  ],
  "total": 1
}
```

#### GET /api/queue
Get current scan queue and active scans.

**Response:**
```json
{
  "queue": [],
  "active": [
    {
      "id": "scan_20240130_123456_0",
      "url": "https://example.com",
      "status": "running",
      "progress": 45
    }
  ]
}
```

#### GET /api/stats
Get overall scanner statistics.

**Response:**
```json
{
  "total_scans": 100,
  "completed_scans": 95,
  "failed_scans": 5,
  "total_vulnerabilities": 450,
  "severity_breakdown": {
    "critical": 10,
    "high": 45,
    "medium": 120,
    "low": 200,
    "info": 75
  },
  "queue_length": 2,
  "active_scans": 1
}
```

## WebSocket Events

### Client → Server

#### connect
Establish WebSocket connection.

#### subscribe_scan
Subscribe to updates for a specific scan.

**Data:**
```json
{
  "scan_id": "scan_20240130_123456_0"
}
```

#### request_stats
Request current statistics update.

### Server → Client

#### connected
Confirmation of successful connection.

**Data:**
```json
{
  "message": "Connected to security scanner"
}
```

#### scan_update
Real-time scan progress update.

**Data:**
```json
{
  "scan_id": "scan_20240130_123456_0",
  "status": "running",
  "progress": 45,
  "message": "Analyzing vulnerabilities...",
  "vulnerability_count": 3
}
```

#### stats_update
Statistics update.

**Data:**
```json
{
  "total_scans": 100,
  "queue_length": 2,
  "active_scans": 1
}
```

## Customization

### Branding

Edit `templates/base.html` to customize:
- Application name and logo
- Color scheme (Tailwind CSS classes)
- Footer information

### Scan Options

Modify `web/app.py` to add custom scan options:
- Timeout values
- Concurrent scan limits
- Scan depth parameters

### Report Templates

The HTML reports are generated using the existing `ProfessionalReportGenerator`.
Customize report appearance in `report_generator.py`.

## Security Considerations

### Development vs Production

**Development (Current State):**
- No authentication required
- Debug mode enabled
- CORS allows all origins
- Plain HTTP

**Production Recommendations:**
1. Implement authentication (Flask-Login, OAuth2)
2. Enable HTTPS only
3. Restrict CORS origins
4. Use secure session management
5. Implement rate limiting
6. Add input validation and sanitization
7. Use environment variables for secrets
8. Enable audit logging

### Data Privacy

- Scan results contain sensitive security information
- Implement proper access controls
- Consider data retention policies
- Encrypt sensitive data at rest
- Secure data transmission

## Troubleshooting

### Common Issues

1. **Socket.IO Connection Fails**
   - Check firewall settings
   - Ensure WebSocket support in reverse proxy
   - Verify CORS configuration

2. **Scans Don't Start**
   - Check background thread execution
   - Verify scanner initialization
   - Review server logs

3. **Reports Not Generating**
   - Ensure write permissions to data/reports/
   - Check disk space
   - Verify result_transformer module

### Debug Mode

Enable debug mode for detailed error messages:
```bash
wss-web --debug
```

### Logs

Application logs are written to:
- Console output (development)
- Configure file logging in production

## Future Enhancements

Potential improvements for the web frontend:

1. **User Management**
   - Multi-user support with authentication
   - Role-based access control (admin, analyst, viewer)
   - User activity tracking

2. **Advanced Features**
   - Scheduled recurring scans
   - Email notifications
   - Webhook integrations
   - Comparative analysis dashboard
   - Trend analysis over time

3. **Export Options**
   - PDF reports
   - CSV export
   - JSON API for integrations
   - SARIF format for CI/CD

4. **Collaboration**
   - Comments on vulnerabilities
   - Assignment and tracking
   - Integration with issue trackers (Jira, GitHub Issues)

5. **Performance**
   - Scan result caching
   - Pagination improvements
   - Search index for faster queries
   - Database backend option

## Support

For issues or questions:
- Check existing documentation
- Review code comments
- Submit issues via project repository
- Consult the main README.md

---

**Note:** This web frontend is designed for security professionals. Always obtain proper authorization before scanning systems you don't own.

