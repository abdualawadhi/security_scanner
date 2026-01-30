# Quick Start: Web Frontend

## 🚀 Getting Started in 3 Minutes

### Step 1: Install Dependencies

```bash
cd /path/to/website_security_scanner
pip install -r requirements.txt
```

### Step 2: Start the Web Server

```bash
python src/website_security_scanner/web/run_server.py
```

You should see:
```
╔═══════════════════════════════════════════════════════════════╗
║     Low-Code Platform Security Scanner - Web Interface       ║
╠═══════════════════════════════════════════════════════════════╣
║  Server starting on: http://0.0.0.0:5000                     ║
║  Debug mode: Disabled                                         ║
╚═══════════════════════════════════════════════════════════════╝

Press Ctrl+C to stop the server
```

### Step 3: Open in Browser

Navigate to: **http://localhost:5000**

## 🎯 Your First Scan

### Via Web Interface

1. **Open Dashboard** - See statistics and recent scans
2. **Click "New Scan"** - Navigate to the scan page
3. **Enter URL** - E.g., `https://your-app.bubbleapps.io`
4. **Enable Options**:
   - ✅ Verify Vulnerabilities (recommended)
   - ✅ API Endpoint Discovery
5. **Click "Start Scan"** - Watch real-time progress!
6. **Download Report** - Get professional HTML report when complete

### Via Command Line (Alternative)

```bash
# Simple scan
python -m website_security_scanner.cli.cli \
  --url https://your-app.bubbleapps.io

# Scan with verification
python -m website_security_scanner.cli.cli \
  --url https://your-app.bubbleapps.io \
  --enhanced \
  --verify-vulnerabilities

# Batch scan
python -m website_security_scanner.cli.cli \
  --batch urls.txt \
  --enhanced
```

## 📊 Dashboard Features

### Real-Time Statistics
- Total scans performed
- Active scans (currently running)
- Queued scans (waiting to start)
- Total vulnerabilities found

### Charts & Visualizations
- **Severity Distribution** - Doughnut chart showing vulnerability breakdown
- **Scan Status** - Bar chart of completed/failed/running/queued scans

### Recent Scans
- View last 5 scans
- Quick access to reports
- Status indicators

## 🔍 Scan Page Features

### Single URL Scan
- Enter target URL
- Configure scan options
- Real-time progress tracking
- Automatic platform detection

### Batch URL Scan
- Multiple URLs (one per line)
- Sequential processing
- Individual progress for each URL
- Combined results

### Scan Options

✅ **Verify Vulnerabilities** (Recommended)
- Actively tests detected vulnerabilities
- Upgrades confidence levels
- Provides concrete evidence
- Safe, non-destructive testing

⚙️ **Deep Scan**
- More comprehensive analysis
- Additional vulnerability checks
- Longer scan time

🔌 **API Endpoint Discovery**
- Automatic API detection
- Endpoint security analysis
- Authentication testing

## 📈 History Page

### Features
- Filterable scan history
- Search by URL
- Filter by platform (Bubble/OutSystems/Airtable)
- Filter by status (completed/failed/running)
- Pagination support
- Direct report downloads

### Actions
- 👁️ View scan details
- 📥 Download HTML report
- 🔄 Re-run scan (coming soon)

## 📄 Reports

### Professional HTML Reports Include:

1. **Executive Summary**
   - Security score (0-100)
   - Risk level assessment
   - Total vulnerabilities count

2. **Severity Matrix**
   - Burp Suite-style visualization
   - Confidence levels (Certain/Firm/Tentative)
   - Color-coded severity

3. **Detailed Findings**
   - Vulnerability descriptions
   - HTTP request/response context
   - Evidence and payloads (if verified)
   - CWE/CAPEC classifications
   - Remediation references

4. **Security Analysis**
   - Security headers assessment
   - SSL/TLS configuration
   - Platform-specific findings

5. **Platform Details**
   - Technology stack
   - Detected components
   - API endpoints

## ⚙️ Configuration Options

### Server Settings

```bash
# Custom port
python src/website_security_scanner/web/run_server.py --port 8080

# Custom host
python src/website_security_scanner/web/run_server.py --host 127.0.0.1

# Debug mode
python src/website_security_scanner/web/run_server.py --debug

# All options
python src/website_security_scanner/web/run_server.py \
  --host 0.0.0.0 \
  --port 8080 \
  --debug
```

### Environment Variables

```bash
# Set secret key for sessions
export SECRET_KEY='your-secret-key-here'

# Start server
python src/website_security_scanner/web/run_server.py
```

## 🛡️ Security Notes

### Development vs Production

**Current State (Development)**:
- ❌ No authentication
- ❌ HTTP only (no HTTPS)
- ❌ Open CORS
- ⚠️ Suitable for local/trusted networks only

**For Production**:
- ✅ Add authentication (Flask-Login, OAuth2)
- ✅ Enable HTTPS
- ✅ Restrict CORS
- ✅ Use environment variables for secrets
- ✅ Implement rate limiting
- ✅ Add audit logging

### Scanning Authorization

⚠️ **IMPORTANT**: Only scan:
- Applications you own
- Systems with written permission
- Testing environments

Unauthorized scanning may be **illegal**.

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Check what's using port 5000
lsof -i :5000

# Use different port
python src/website_security_scanner/web/run_server.py --port 8080
```

### WebSocket Connection Failed

1. Check browser console for errors
2. Verify firewall settings
3. Try different browser
4. Check if using proxy/VPN

### Scan Not Starting

1. Check server logs in terminal
2. Verify URL is accessible
3. Check permissions for data directories
4. Try debug mode:
   ```bash
   python src/website_security_scanner/web/run_server.py --debug
   ```

### Missing Dependencies

```bash
# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall

# Check for specific package
pip show flask flask-socketio
```

## 📚 Next Steps

1. **Read Full Documentation**
   - [WEB_FRONTEND_GUIDE.md](WEB_FRONTEND_GUIDE.md) - Complete reference
   - [VULNERABILITY_VERIFICATION_GUIDE.md](VULNERABILITY_VERIFICATION_GUIDE.md) - Verification details

2. **Explore API**
   - Try API endpoints with curl/Postman
   - Integrate with your tools

3. **Customize**
   - Modify templates in `src/website_security_scanner/web/templates/`
   - Adjust branding and colors
   - Add custom vulnerability checks

## 💡 Tips & Tricks

### Batch Scanning
Create a `urls.txt` file:
```
https://app1.bubbleapps.io
https://app2.outsystems.com
https://airtable.com/app3
```

Then via web:
1. Go to "New Scan"
2. Select "Batch URLs"
3. Paste URLs (one per line)
4. Start scan

### Keyboard Shortcuts
- `Ctrl+C` in terminal - Stop server
- `F5` in browser - Refresh dashboard
- `Ctrl+Shift+R` - Hard refresh (clear cache)

### Performance
- Scans run in background threads
- Multiple scans can queue
- Verification adds 2-10 seconds per vulnerability
- Use "Deep Scan" only when needed

## 🎉 Congratulations!

You're now ready to use the professional web frontend for security scanning!

### Recommended First Scan

Try scanning a test application:
```
https://amqmalawadhi-85850.bubbleapps.io/version-test/
```

This will give you a feel for:
- Real-time progress updates
- Vulnerability detection
- Report generation
- Dashboard statistics

---

**Need Help?** Check the full documentation or review the code comments for detailed explanations.

**Found a Bug?** Submit an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Browser/OS information
- Server logs
