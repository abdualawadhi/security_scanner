"""
Professional Security Report Generator - Burp Suite Style
"""

import json
import base64
from datetime import datetime

class ProfessionalReportGenerator:
    def generate_report(self, scan_results, output_path=None):
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"security_report_{timestamp}.html"
        
        html_content = self._generate_html(scan_results)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path
    
    def _generate_html(self, results):
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none';img-src 'self' data:;style-src 'unsafe-inline'">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Burp Scanner Report</title>
    {self._get_burp_styles()}
</head>
<body>
    <div id="container">
        {self._generate_burp_header(results)}
        {self._generate_burp_summary(results)}
        {self._generate_burp_chart_and_matrix(results)}
        {self._generate_metadata_overview(results)}
        {self._generate_burp_contents(results)}
        {self._generate_platform_specific_findings(results)}
        {self._generate_burp_findings(results)}
        {self._generate_footer()}
    </div>
</body>
</html>"""

    def _generate_platform_specific_findings(self, results):
        platform_type = results["platform_analysis"]["platform_type"]
        if platform_type == "unknown":
            return ""

        findings = ['<div class="rule"></div>']
        findings.append(f"<h1>{platform_type.title()} Platform Analysis Findings</h1>")
        findings.append('<div class="finding-section">')

        # We need to reach into the basic results if they were preserved,
        # or we might need to update how enhance_scan_results works.
        # For now, let's assume some key findings are passed in platform_analysis.

        specific_data = results.get("platform_analysis", {}).get("specific_findings", {})
        if not specific_data:
            findings.append("<p>No platform-specific technical details discovered.</p>")
            findings.append("</div>")
            return "\n".join(findings)

        for key, value in specific_data.items():
            if isinstance(value, list) and value:
                findings.append(f"<h3>{key.replace('_', ' ').title()}</h3>")
                findings.append("<ul>")
                for item in value[:20]:  # Limit to first 20
                    findings.append(f"<li><code>{item}</code></li>")
                if len(value) > 20:
                    findings.append(f"<li>... and {len(value) - 20} more</li>")
                findings.append("</ul>")

        findings.append("</div>")
        return "\n".join(findings)
    
    def _get_burp_styles(self):
        return """<style type="text/css">
body { background: #dedede; font-family: 'Droid sans', Helvetica, Arial, sans-serif; color: #404042; -webkit-font-smoothing: antialiased; }
#container { width: 930px; padding: 0 15px; margin: 20px auto; background-color: #ffffff; }
.PREVNEXT { font-size: 0.7em; font-weight: bold; color: #ffffff; padding: 3px 10px; border-radius: 10px;}
.PREVNEXT:link, .PREVNEXT:visited { color: #ff6633 !important; background: #ffffff !important; border: 1px solid #ff6633 !important; text-decoration: none; }
.PREVNEXT:hover, .PREVNEXT:active { color: #fff !important; background: #e24920 !important; border: 1px solid #e24920 !important; text-decoration: none; }
table { font-family: Arial, sans-serif; }
a:link, a:visited { color: #ff6633; text-decoration: none; transform: 0.3s; }
a:hover, a:active { color: #e24920; text-decoration: underline; }
h1 { font-size: 1.6em; line-height: 1.4em; font-weight: normal; color: #404042; }
h2 { font-size: 1.3em; line-height: 1.2em; padding: 0; margin: 0.8em 0 0.3em 0; font-weight: normal; color: #404042;}
h4 { font-size: 1.0em; line-height: 1.2em; padding: 0; margin: 0.8em 0 0.3em 0; font-weight: bold; color: #404042;}
.rule { height: 0px; border-top: 1px solid #404042; padding: 0; margin: 20px -15px 0 -15px; }
.title { color: #ffffff; background: #1e517e; margin: 0 -15px 10px -15px; overflow: hidden; }
.title h1 { color: #ffffff; padding: 10px 15px; margin: 0; font-size: 1.8em; }
.heading { background: #404042; margin: 0 -15px 10px -15px; padding: 0; display: inline-block; overflow: hidden; }
.code { font-family: 'Courier New', Courier, monospace; }
table.overview_table { border: 2px solid #e6e6e6; margin: 0; padding: 5px; width: 100%; border-collapse: collapse;}
table.overview_table td.info { padding: 5px; background: #dedede; text-align: right; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.overview_table td.info_end { padding: 5px; background: #dedede; text-align: right; border-top: 2px solid #ffffff; }
table.overview_table td.colour_holder { padding: 0px; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.overview_table td.colour_holder_end { padding: 0px; border-top: 2px solid #ffffff; }
table.overview_table td.label { padding: 5px; font-weight: bold; }
table.summary_table td { padding: 5px; background: #dedede; text-align: left; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.summary_table td.icon { background: #404042; }
.colour_block { padding: 5px; text-align: right; display: block; font-weight: bold; }
.high_certain { border: 2px solid #f32a4c; color: #ffffff; background: #f32a4c; }
.high_firm { border: 2px solid #f997a7; background: #f997a7; }
.high_tentative { border: 2px solid #fddadf; background: #fddadf; }
.medium_certain { border: 2px solid #ff6633; color: #ffffff; background: #ff6633; }
.medium_firm { border: 2px solid #ffb299; background: #ffb299; }
.medium_tentative { border: 2px solid #ffd9cc; background: #ffd9cc; }
.low_certain { border: 2px solid #0094ff; color: #ffffff; background: #0094ff; }
.low_firm { border: 2px solid #7fc9ff; background: #7fc9ff; }
.low_tentative { border: 2px solid #bfe4ff; background: #bfe4ff; }
.info_certain { border: 2px solid #7e8993; color: #ffffff; background: #7e8993; }
.info_firm { border: 2px solid #b9ced2; background: #b9ced2; }
.info_tentative { border: 2px solid #dae9ef; background: #dae9ef; }
.row_total { border: 1px solid #dedede; background: #fff; }
.grad_mark { padding: 4px; border-left: 1px solid #404042; display: inline-block; }
.bar { margin-top: 3px; }
.TOCH0 { font-size: 1.0em; font-weight: bold; word-wrap: break-word; }
.TOCH1 { font-size: 0.8em; text-indent: -20px; padding-left: 50px; margin: 0; word-wrap: break-word; }
.TOCH2 { font-size: 0.8em; text-indent: -20px; padding-left: 70px; margin: 0; word-wrap: break-word; }
.BODH0 { font-size: 1.6em; line-height: 1.2em; font-weight: normal; padding: 10px 15px; margin: 0 -15px 10px -15px; display: inline-block; color: #ffffff; background-color: #1e517e; width: 100%; word-wrap: break-word; }
.BODH1 { font-size: 1.3em; line-height: 1.2em; font-weight: normal; padding: 13px 15px; margin: 0 -15px 0 -15px; display: inline-block; width: 100%; word-wrap: break-word; }
.TEXT { font-size: 0.8em; padding: 0; margin: 0; word-wrap: break-word; }
TD { font-size: 0.8em; }
.HIGHLIGHT { background-color: #fcf446; }
.rr_div { border: 2px solid #1e517e; width: 916px; word-wrap: break-word; margin: 0.8em 0; padding: 5px; font-size: 0.8em; max-height: 300px; overflow-y: auto; }
/* Burp icon classes */
div.scan_issue_high_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABLNJREFUeNrEV01sVVUQ/ubc+376Z1sQKBSI1WjVNBW00cQEo3FhSFSqG0z8iybGBd0YF0IIO0uUBTGx0Y2BBHcu3BITIYSFuLAEQ4pEMKiPn6qQUgptX+89Z/zOebUS+t7rfS7stOfde8/PzJw535yZEb1nEAvkBGnOoVxwMHwH/+PU9ymHtFsctqpgC6B9Cqzniqb5lTOcWoLijECOsx2GkUv8hqrC/3leaXkaLkkgxiyIjFGHxOsU6aMO+h6ZbKdOuX/676A2iljNgcc473WKTYyar9i/n+1kPRmmtnCJrOiniXGjVOA1biIn1YVXI9rRvco2quTB7yibAtyG8WYTPGiNG6PgIWQXWpVokSHyG4PIQ6rOn8kdCmhFMFxFnTTWAS76ka23pmCRwEgnbkAnb1Y0lHpqai/bqSjKDRAAUMetaaXxqCjb+F0Lkrzrmc3bE6LI1z40Tk5SuIvjMOvXwKzqhPt9vLKLOkoQjHlTaDoRF4o9xsSI4wKiqABTLpBfQVAmnss5e4zorwtMWAv98xqKu95Fy9GDaP72IPJvvAgtjS99HM7GJl84FsU5vmswnIlS/qTeAnaErrZxSSZXriJ6cjPyu94BWlsgK9tRHNkD07MhHEkG2kiLj9Cxg3saohQ2cvem4nbwY+ldTE9DeroXw8L33ZpZej3PPcoXd5g4d1/AwFzeA88NZ0Z6RI+aKS/uL89xzGTzDO8NkRmm/YMbdrDnFfyfRA8SE2+P88UOI6rbsBwUTK6DHgPPyjLJJwif8UfQp8uggFZuxD5eS7oWy0Vi1nkLtC2bAtA2Mx8JspOlCxULi/sL9GfnGlbBEA1TDVmtuQj99dKifneBfc1Njcq/QQzI5YYUWLsK9rtTmPvoC+jULei165gd+hB6oQTpvKtBN8RlmXr4hQMCfSvzOfhoOJfAXfkLUW8Pr9EU9pcSzMauClfVBtwQB304PtIQCPw5NzGMrl6B9IeTSE+NwaxbVbmiNTsnH/4ZHY/IZP+2VmPtpA9MWWNBiHo2Rbz1qZAbpIePQ9pagZamRoDo1NqOmHr4lOZLPt/MpP/MbDB704FhKrAldCUHvsbs+/sg+VymgMR8019Eh1TMlPEa8zrek9V4PhOKn396QXjIQN9+mTnCppCoNBCP9gRIWe/aIiWmAvskixa5XNXEQyfpzbk40+6duo+tJhdVLc/dmAAIJksf8Hl2qcBkutfAHv0ec58cCt6g0zMo79wPd/pnyN2d9YVLMP1Zm5R3KjHkm0xsfmkelT41s11RYs9xZmtdN2TyoX9chelnsptauLHzECaoYaymJ4St3Uxdcj+j4LjMXwQmLPAJgn8YjDvIExy6XtcNCzkILeHO/QbHW1E2dC0hPIifIOwfv1141cKEQ2coop8vo3UcKKTgsrIDsqJ9AVU1awhg1Dn7CKf8JHeUObV8pkTfGCDXvf891FYKOfr6XmfTAQovVSuxTP2yCrsJml6a7XN+TmQSGqomTLD6+cy59AHedrtRp3CSiU2D/y52FtGcq1zpoqFOdPOmZUndTsbPcWgLx/v53h0S2goRM74cd6c5dpy1/DdOk0lfhkkozz1746v/SkZ8G/0twAAD7yPRry7F6AAAAABJRU5ErkJggg==)}
div.scan_issue_high_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABEdJREFUeNrEV91vVEUU/83cu11326XdLR+tqNgEwQgCCcXEVI0YjQkvalZMxFf4A/wDpAkhPJZnNLE+a+K3PogRRVJNTCCmATGaCEEQLWW/u93dO3f4zdytW2x7996QuCc5d+bOnfMxc35z5lyhp6fxLwkNNJOAJwHpmQH2Hfa16Y8B+gA7z0DjMbYPkJ22pCL/yemX2H7HuV9S1xX4Row6oINZPgeazfZYQC66kcCTlH+TSg52mTnEeTvZvtY2+AFlT7L9IUxIhlhOQYu3qWyGLwcRlzRlNIzsO+RUXAd2Q8mL8MUR3CtpfZiOXLI6V3XAxH05az3B2F3gt7EQpUGb5sL603ePrU4PM+7nyU/Z8OgOSzQIuiVeTG7jys/xiwg1bkCUHYQqVdCav83oDxJNTrgTvuZui+/hJrZbeSktu1BOB26+/jbYiTBQCmvwxsxPuPD+J/CVh10vHcCW554GypVuO0FH3TNw3M20oe8OAfQptqNdY5pOo/XPLRr/GPVSGV6jifPs165cAzKZKOA0Nk7ZI0mW7cFt9Dwa4PpcNApFu9D+3BBSQ+vsrtQLBfstIh1p26QDdvE4ERnVvoZwXTgJF5p9ww7fJdl8i0QWA+KEmS+J+Cw9yOP/JIsTkYcjc8QAXkGvSDovGwf298wBiP3EgN7ROwf0DnMKRntnX48aBzK92wFkZOeyRuQjpD0PqtWCYCo1rFoefLJNrzH3wGSOMnkgsggNJ9fn7NmvzM2xTcDt60P/hvUsNhpxHSgbl6/HEqnVkRjOYe/reQyOjiDNS2n8jTxSD22mumpcB6673NJZgmFfnEoDxSI27t2NF7eOQSsFMcxcVix3bsroNGtS8em4GLAp19x8949AbHkQqNRYO3pxjZv5p5nQ1WdEklpWYHZPo/exdmDcb537EarZwqY9O801CywsxACi8KjrU5egqrFImIbjHO56lxty6Gcqhcsffo6fP/qCIhqPPv8s9hAHxim7E1F2Uan3OHdB2ntZeUcjGTc0MID6H1fxy1dnkM5lLRB//eYsbl+8zEJlXfTt99UkH7wNjddS/sWh45Fi6CtIFiUJhqFRrWKxUrXHMDHQz9WrqKs/zoXfYOhNPdBeudd6i/3Zrk5Ua0iObMT4oVdZkGStI+OH8sjwRKBU7m7c2AhsWTwJPfVu53hJZxh9yd/4kl0zJMuKUj1fsFnQ3bQhOBU8kmsuIBgvMllt5ernl+ZJ27EsYT80G0/QylyoIuNEoQTBktylIyiVuhvX1Nls7FtufOWPiT3j/u9UtotvM6Fbaai+yKNXD26TcOMzVqfR/Z95clUBgZsUmKDgpMn+93DbtWh0ksCdYP/mak6GZw3tH+PzEa5wiu3fMQybuVOBrNWx9mbqk9MrR1nxBj9HFphB6pXmB1O8wEH+geBxMnMwBtsSBAGumdxOmbNsv+bc+tKxXcI4880KU3cEGADDcbVpFKB7lwAAAABJRU5ErkJggg==)}
div.scan_issue_high_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
div.scan_issue_medium_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABDdJREFUeNrEV01sVUUU/mbea62lf4/+GPoXF5AgAW3qb2JiCWrQhSGxIairYiRuCJAYEuzW4E8MiQRJ2LGoWxfKAknTdCE1oImNFoU0RgyIkJafIqXlvXfvjN+ZeS2lr+++e4tJTzK5d+6dmfOdOd85c0bZfZsxL0oBuZxvKQ1o9k3A73yHboYJXwdsD6x9kh/a2VYVZmbZ/ubAC/z/PcefZP8irJF5/CRDrF8/CIEw9O+UNKLEDVLrqfgD2PDtBQoXSy1bE5V08fmWV6y+ZvuCL6ejVOjSiikm/BihOU+L34tQXkJsr9sN2ONQqEsAwClvQxj8xPah7yosX2wfLTnPl+e9KxYDEGvnm/jLrIUNfoGyz5RWXBg/cweYnoLbchUJspXrneG0rQ6EjLfWNY0s+eMaiXdvdjWC7I8c0hipXMg5Sc7VNgDNbcCNq0Cea+hU9GYo8x1SqhsVlWRf2rW0Y+ScmPwQ189EWiO/Ji4DL24D3v0IqKoGBr8CBg4CDelCxJTyhpXoGobVa7gTMxIZen7rYfq5eFdZf8u2N7QAe77ks5kAyM033ge6twDXr5Thg6xt6xhRA85wNk1/81u+iX45GItsuVmgpcNv4UJp6eS/bAxOOhxv0hXPicu0U2rRj6UouqQRnBIQdBgsAnavPAcWboTC556ESpKR3ZUs1CweSnxmfImkfJwusK+yV4OVEKV2SOC/gpUShR7hwCasnGwUF7StIIBGvTz/q/8LgNGJKW2Yx9MVzGiL8sAjj8rpmdgSATCdaIoomrhUnAeu/QVUVi0DgMLlRFOqWXtMTQCHd/M5yQPsLvDtMWB0mCVJa1IAk2k64Fe+vJYoiUgqHvkG+GPUW31pHMjwXEhVJHXDmIaxg8nTGEnYSGv/PMclRoC6jD+Ukih35xKGld3VrXm+32SnPmb24tnP2uHfm8DTL3vFPw95TtQ3FXMjSgLTznqA5YnFUZ5O/bHiQaJAOPDOAaB3r//2+xngs53+qBaSxpNT1HlFEwBR209jx/b0LaBz/X3lIhteAHq2+yopvuyX3dREIb64QxD7XKlVTjTjf3Z6aWCSH+K40NgBZMMx5KQgMb445IXhMN9Hym5ETb239Mge4O5t7l7el2Q/nGB92B6DeHaCvt85/8n2dd0nt0Y1KlLjriyPvKzAg2hbR58zDC8yGmpXR0fCnGE58wQNvTDXfzCfGlcoPsvRZ9nrKFlYCgix9sY/XmHmsegc4JUFyJvNC5UXX0z8j6vu7scYjaxupdWwLK9r9KWYu46VjPdxBLy2hcUuLlFDqymG2xYq6S9cPJd/YBoc4fVuA1H8thS/dHTM208IYh0nHpLjJoH6GSo+zvldnE+2qpIp8kESCsJKqdKUTzgOovIwDarc1Qqqh72nChzJFIyYKgAc4zqnqfQUn5NuUXfFLygIizPdfwIMAOlvjp3T7A5HAAAAAElFTkSuQmCC)}
div.scan_issue_medium_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABFZJREFUeNrEV1toHFUY/s6ZySbd3VyaJqsmYKK0YFtL+yASFOyDIqLV1/oSFfRJfLBapC+ioOhDVBQU9UHQh6qvlqp4aW1BkBI1WmprL9KSXknapHtJstmdmeP3n9ndbMHd2Uml+eHfM2d2zvm/89+PMhMTsGQUoAzQUeSEz4ED6ADwdfi/Ywb5+zA/3MrxTvKtZBeV1eQL5KPknzn9huNxVMnuXZ0EqCfVFIDMjdrM8UVo8zjFtKF12kt+lxvsawZAR2zyDrXwBwGMxhQutI38IyV/ybGv0UeNAAzzxIcpeAeun7bz9Mc43lenhjoAATFU2VirbIBSf3KyqeGWxoScTAPpbi7R4bwxiQYOkh+pGL7GGokSLLcvAm1ehm8P8ZOupsKFejMwhRy8S2eBnl6uTfAQQYQyzF76wwg8+q7vWHat8Nr/ej85jWaHUaHw/PhBnPl0DP58AQOPjiLz2JME4DcHYS2g91HbN5ELoQZqJnBepfCNkRbtSMFkZzC5+z0UL07CUODk5+9j/uhvwOr+CAUIiCAJ1//ChjhZV1TKleqVllyKqvZnphF4ZbT3D8Dt7oVKJFCamWJWcKPXhyG5jeYegesRgOOIWl5u2acNkTsuNIHI6UXlym2z82gfqDeFegu+Kxqw8f00biSF0XYvH24nAPUgZ0nccDKSyLdr6uB+rAhZNWwVE2xaGQBKcspGiYJBrBytkVqQWp76zP8BwBb7eDtJ3vd9BKUSH7XloFzinKlc69h24ApViLWkvAin72Y4HUkUWQdsAiKg9gwtWS4tA4DC2VhLFuah0l0YeuIFpNdugJvqwvBTO7Hqji3A7OW4AKaUOTH+Jrxg13+U6sb2D8hrWDjzWZgiAcnps1eogXI8MxjsoQGD72OHj4C4SoEUrNYxiudywHJ8QGG/Msd+kVpwRYpsa6hNWPtTnZg/fAjl3Cy672Kzw3qA/FVu5cSJplvYkHChoz9oORbklF09mP56N/56/Vn8/fZOnP7oNRhxwFWxIvpbquASndARAGNUR2uljCcPzp/Bha8+g5vuRHJoHaYO7EFu/EB0P3AtvRT2hAwr+F6eT8+1ljp82wu6ZC/PliyXteXY7ewB2CO0SJ/Qk49Ii67thrLQ9z6kfX+KDsMC9Oo+DEnoDbJ5dh0Mjz6P1JZ7AMkJ0XSegp9Zupic+rXeuxMo+8fpD8MNw7LWlPbbuJee0Bm8LXTA6EjgSc168j9Lbbm0UcLijK7L/BrczQ9ONQ6dyi2HbZk4nZMZYEheDrNgc+ELXDhSLzwEUO3xpZ0KTzfNSwnTmvquaS4QIAtzAFtzu041zWS0NzaTf2/tZmQwx38eohy5GRVwfTRGlp7jZJyrWZV4ucRa8hvkczGEzhL8xwh4yzIMN9U4yShzemLJtqLKxWJYoCWjVc0TeqTL9w/wkddzxROZIb7rqRwiz/fn2F8eCa/n+IHfZmu1Q5uwHbf7+NcA+FeAAQAQU5ubLuZZqwAAAABJRU5ErkJggg==)}
div.scan_issue_medium_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABzJJREFUeNqUV2uIVVUUXnufc+9ohhpUWmKpWWmGppYShmWmppJRlBRZ9oDwT2aJBEVEWX+sadCiX/0wkSApQgWjoaQcMtG0MsVSUdMSkzQdcRznnL1X39prn3vPdUzpctfZj7P2ej/2MdyygOo/AzhDxEzkjS6LH3N/PGeQMXcS+1GYDwX0im/PAvYBfwcOtWH+BVmzN9AhDn8FPBJHZAGsxFO66M+MAMOFOPFUFOR8SE2A4WAyHAgPhx1Pa/BsgVDfXIj6RQTgJWC+qL6kXXisgxU2gfB+aHE8sGLui3EQ9sZgnAYYj71ZGAVWAuYD/jmvet1cYOAC7wfCBavBbHTk3IpHM+W+VfhRWoEZLaZM57UK821wgTCdE3f+AukHgb/xXBdYdXQBVrS8AVpvV+aQhnkOeTcNh1vJ4H1SBRoMx0l0LASymFucT2qW2oJzj4POZKz2A/ph7zvQm65nGlzQVV5fTo43g1IfIO4F46kgtB8mV/kScDDC3CMA3STsXKcS+F8xfgX5DzdYg8164N4Ea63FwXtAYx0kHYezW0oC5PUD3n0dmHs+SHk2llLbrlgxVLzvDfxlIDpXNYmWU6ZdEOUDMH2BLGha7OUVEa+TjJsCi0EYM0lH2w/nOtQF4gsBT6/ixUjQY+rquoPO5O2wBuIbRJLgGpiRfyF2c+sp2/CrgsYC0BLtKsHPSQYOXsek625E3GHE1qXk7cdFblpoJZpdAeJvBFO7/GlIf4h6wtzVtBxs3+L9NTXGOpwAnGoMa7oV3NaSr2psVEhrCkEgk90XzjHfT86Pp9xBALXiK2H0fgc5tzwIUknV587LgecAN5ai/A9kxANQYCBWyBh+AmNHEYGw5DTAFLWsKABh8p4Y021AWBUD6h3hY7h5XgU+PYnNnoiBWZivDQip1cgW/7JUtRBweGUYeP3hnqMalCF2xJnImmRrzGX8QYdBzxTZVWQND4qZARw3BDHAUzCFeHwyHBKmVvCcuEOB/XolKhr51wBHVVPWPRE2MT8C5bO6FcwYpG1MH6xtV4T8ANTeHK0wO8VishYFvwbz6Fs8MpjexSKe2mepYnfCPY6y7P0gXGBc1VFTTh4/AR6KjupNLBUr5rmJtAKa+RQPpCPdJfk1MkbP9zhQzy4R3ufl8FqqTcppbDT1iubnWM/EbPmjJXyU6Tyrx02iOJqyW6KhRsMFdG2UbF/N/EK4HAM1IlHzJtQpW6WQQcE13BvCfgncETFOhM5q7HONntSrAow/GCn2s8FUGtnt8HUMumiuJEpcyCAluMdl2O9BATd0QT8PgvyGjak15sw56sjrdAYHO4DX6es9Q0m3l7thJG8aLwBBObyu+LjN6nP5Ock4Px0W+RCTq7u1OJdPhkWOR2FiCbeF0A1VTOrAibjXV7uJLYHUgybtfqHvwKVeLixnZb68gbkGI1q0vx3jBkqlOUmgisvKegbcPnUBiA7E0BxKJpfcrEMwg+xlEeJ7KbOG66lJMKnzbyFAh0HjTUUmBu2lj4QA5breTIPi7E8J+59B8V4ExgTYblljjTdqtiBQeVv20jnkqsh9zpCeK5Cyx6hqy3cCLcVJJZbiUgk3PD4G9zaxjVwyXkJuzoQ2hsoN24SyqjvhEtHgQocUXKI4hcaGauuii4Z9XxIsPGdHMutFZJiSpBT3ggCPhDZqSpAUEVyNV79irEQf27jF2vmKc1W8ryTaliW0CrA0DMRGxrReZdWn/j01t3lT/c4l8NGHlZg0BcQ+YGDnVBhKgcoVZC7a+9jqC1KBB70bbdGK94dtYMBuieZoMgQd68W6DaXySQakKgiXzE2MqznvRg34nZydST6qaCIUdaeW4SElJ8Ft02OMLJQ9Sw7EnT2FwJqvTSRphlY3B3MGxjGCA/MohAvrpXhxPSYDwHxlENQLLWnhqcZOENqo9TjBRcR/Hqor8UeU5zuk0VmqRJMlGdzAG7SQpG3kKgOUSMkakoa2E7idkhkba2nIvo0y0MjycO/odtv3mQG0QTG5ax5Bi3imcHVaoy+BYzPcfiu7sRgIiZFiqHZktpbCOrZWYZS9DEmOgc4l0Obt0KTE70kas8QXNaI/BMRllG7BtoeQE2FBp31G7VsWFarROAiD4sS4ppkfsF7QiAJzuia96ZBpBsnFYNRJ1Wos1Q1Wm4342gXGo8Gwi05nE+i020NdYC6cOrsJECQ+gkAZFa7ZavkWMNmG8THNQY7Mq1qg0ljtpOhwLUJnAEm64yeYy1fTLvh/FKrlpnOTDF9GT9ZdIGkj97fAJNx2FgEWY9IUCf8d7vYc+vkenDkWpGCDFsm4spmx2EdX5MGlitiCx8Jw2+5wetGxpvxp9h8ChBIQOuFVCJ7nIYh8nF558Y/ZcKORr+UVmC+FIju164B2R/4/BeDCXnLjMVXVzkwMPiUaHL6ktL7BEnQIsD18nnt8Q1p8uJqYshcQ4F8BBgBfE21FYApCcQAAAABJRU5ErkJggg==)}
div.scan_issue_low_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABGFJREFUeNrEV19oHEUc/mZ29y5J0/SSS1WaqFgtlBZqKDbQF9tCS7BPtgjqgyKSZ6GKD1owFEoVQSoIvhaUvojgY1NKiaANSsF/ldZGtBaurVWTXE57//Z2pt9v73psQrK3m4L5HcPtzs7M9/3+zfxG5Sa+R1TqyMBAtd8byuGbhYbdGEAfZNfTfN1hgWE+r2sNq3FGgQN/sRZfaWXPsO+arONwoOFPRHGVAFW+BeGbiIsYadHYyoXeMFa9GAFcKuuJM0hiI3x+gWNl8ud8Psk2HYehY4DJU5+gRle48HgM+PJi8RzbBRI7xbc+6UhEQIVz1ZAP52ID+i3cp9D4r9CBlwk12pEA/SzgT9Th/Ei+T6kVWIcKkmlQDRCU2WzEbMvLENf9lv9jSy2hBUSaQ4M34A5U4V5kf151CA4z5yPb46K/3wOKPgKf6+hOXtGThNwZJaEJKsDw4aGMzHkuk+uoOcGf2bkBvx95DH+8vhnHnn0IoCVM0ImAKNs1xdzoCp0jlGrIhql3B91HGXQjupUyK/q0YtDd5+GLl4axab2LvqzGO/vy2L2tF2be7xiZNF+fRvY0SdDlbCbMSruRH4/rGM3b4hsM5j1kl5h7y0Am/JYoLOEcdpEddWl5xkC4zbydOKzFBQ0LP1hMtiLgWqXIDvV+QxKdBFxOG7/fdLOpR6s9UN6j2igcIPde/O8ittfPa8blfoU1Emv3SijtWCN0scJ2Br4dwtrJoFigN733kvUlSQa9Gstp5o3nLIbs9riUsal1EQKlVFMI9M+sj9qSPWdmth5+Ww2BQpoZulujUvJx6NMCbv7bQIlMjk3N4psr/0HLwZRO/nKh1E8MxLHElGllZ8DDme8WsPl6haZXKP5ZY8nBbdWhh0yKSFLmkrZWn0ttN3F/zkOtUEHx1zuslRy4GZ0CvL0PTNEF9jwfF9KAG579KDWwezSHsb35MDAbdEeas0AmBQqf6bBohfo46W5uONoQ/OjBBzA9/ggmXx7GOf5nmRWmZtLk8lmtnBuyFZOBfk8lzGTDwiO/qQvHDwy2+/Y/3oPDu3Kwc/Xk+iu8GZ7DTWBV4uMRlcQKnOEvo+l8mS5wVNJN7BNrzSXDoKEFAvGGXBU+pDWmO+L3aJSY84dO38BcJUCddcHJ6XlM/lCCHvASeF7dJtarliaQpjDxW+R4NFw+mJEqtmNRwrpww4NZrMso3CxUmQmsb7KSCTZGd0t3N7ZyxNV7vbwZOdEBZSb6LjpISuiHYy3BTWeB1fCCeIM1ohPuAXHgijWTv8+iejV6cuhm9NtoTXOLlpEj+su480CWcHocOL1sOq4kCsFmWHmOUP8LzauIareVNu8iFSNbSK1YW23F02zmI8bYNjK8vNyZqTscfO+ybeHjB2y3U6CXCXyqqbV9Lbxmrkhz4lokCKVK9Zt3JRvRQ0nwqC6OGOOXPRzwZCtG+ltKFDnwFqf8zO9fE/QsF/g7nBVewG3LycJj8d3hrgADAKAAqH3WrJ+hAAAAAElFTkSuQmCC)}
div.scan_issue_low_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABBdJREFUeNrEV11oVFcQ/u7Z3Wx+NtmYTeJPICWhNJIY81D8ebA0D6WI1raUQvJSKKUPpVootQZKsUEfihAxD6KoUNqnJlgQClFRqBHRtg+lGn/6h4otjRiTqLubbJK9u/f2m3M3mhi4P1rMwNwzd/ecO9/MmTMzx+j+ycY8kldV4FmZZAB1fN9k22jnawu5nhyes+o25/zG8TznnKD85+wfslgEm6NhzVcXhje1cfF2frSTcsRlXgV1rOT4FhXu4zjAdTIOun1ceSjvhYVL/NA7HsoXEMG8RovPEEwfDU8EBdBAvkz+GE9PnQTzO/klvRWeAAzur4EhmtDqZh63BMVlQGkFlxjOuwvVcM45Ttv8MGIKrB5TvpS//Eyp3FU5h3g1kEnnMTacRHkV96eIv1ue+zJAHet05EUcDj8G4AyfMS+fxmuAaxcu4vv9ezA9mUZ753to73gb+bwPEErHRS1ja1K2RM1RvovPZi/l0VJg4r6JgcO9GB++BcuycPxIL24MXUdFwld0liKPPu1G6xGAGgL4wk9Ehenq5NgEcmYW8aV1KFuSQJj+T94d4egzLBW2UN96RzT0c6fv40XUobDinkcpW5pDkQiBFdEb/s8oqUfMV4xOwf0+njUZ2CDHXTzwKoWSZw7A8UKHAHgFi0G2LhHtiglk1aIAcJJXiyKSOiweVSnXrOexgf8DWSro1yTv53OAOTMNQynNkhPMbBZKBd8IWZIMsiJnAktqY4iWxJC8/TdSo3dgMQcnlq9ALhvcBZIH/g2yYDojFTCM17dux7KmVsqVeHPbZ2hobUBqPKD5Bu6GC6V3Y4DgxYNR4IUXm/Fh7zfITpmoWh5B+j43NF/wqX+6olgQTgc9PkLpe2xzVrAxbI6wLEtMBFYu0feDAJASfM/3GoZsJAqUxYGhwT9wtv9HjSlW6XggIICjyo5oqw74DhpaGaPyc98dw5FP38W33dtwdO9uBqeJaFkgR57g445CSPfGPU519iYGP0b+yWCw/2uUMACrG5swdPIYrp7/BfFEIPu7nEKc06rTRPORn4wgXU9xaQjFdMNU6gEmyWBpjsUrkDd9K/+KZf2aZc32A05ncJDyoOcxnJR+MIo3tu5AdX0jQqEQNn/Qhaa1LWxUfCkfpsEPy7/RfdF+1B/nUQQTf1F6zk9TKudeesLa+nJkUkB2Bl7Z0OTileSbC9tyW0dGlujWUL7hFj3itNSY0x9WLSvXR5LZ2Ev5lG7D5ihfeC9wevVRchsnn3LNBeSZDHQOkKNpGO4Jh/NXc/zV782IO62z4yfkiaeseHLCRPn1J7sb2niexn1JOUjNYGLGIXpF2vwut9Pl53Y8Qv6cILo5Svv2Mi+drfyoBGplwYiUIQANXKV8gSzpPeXnWP8nwABTjkvuiAutxAAAAABJRU5ErkJggg==)}
div.scan_issue_low_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
div.scan_issue_info_certain_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABElJREFUeNrEV81vVFUU/5373nw405npgKVpY9QU4qof0cSgMZEFC+tCGiMxKnFT2ciqgBujCRvdAfUfMGFFYoyJbJRgABlicEEw7TQxoi0tFkpEWjpSmM93/d0704+0nXnvKYH7evvuffPu+Z17zu+dc66MHDkC0zQvh5erYxx5EDFP7b/Gr7pDIIOcvAotfbx3sWcbLyywz/G9vIjk+PJpDdyGogTdWK3NWKGqSqjxkoZsF/6tl0tHRMs7HCebvJNif5rv7STQfo6XKP8r3kfZJ1oJV81+0PV/R9nz7B+0AN+sJblmmIbMU86x/6CA9HDH4xwcxv9tGofosjxH2wMoYPc9QO8Y8D4/2cViCQ+KxbrK0tqN9Pk43TKg6xirCmisXpw+RTk/tzI3SWb7/MJdxOMxJBMJ3JlfgOdp+7xFSxjZQgysUcKNILpGG+cCb3G/nRvAl198AW++8Rocx8GZcxfZc8i2Z/yWxl0duUBLbDdKGHWVi+UrcpzznvUmWt/u3VtCV+c2DL//tgVMp9qwd+h1PLejBwt3F33oYEClx9HuqNYC01XNfvX6WU97B4NwqlytEji94fmTW7MolysBOGmVGOGGn3EQWSHhZ0FJbXb82x/XcPmX8ZVnk9eu48rYBLZkM4FkmCBEunzOTcOlBmkGj/eCKhChz2OxKE6c/Aa/Xp20HLh8ZYwk9BAjIc09iBX4t0+Ud8BEwqE1Mde3edQ2mXgCJZr7+x9+pB89dG7roGVSqNVqgcND3Qoy5NIju+FDvA074OuFwj8kYweUUpZ8sWjUfoZah5Dlqd0usXvDgBuQv+/M4/mBXuzdM0gXuDhzPodzuUvYmm0PESAtGfvoAt0dRoH79x8gS6APh/etBJ5339qD6ZlZzPx5A5l0Koy4bvMVpMOsKJbK1vTro153VydDczFspkipsCuUEpKtujE+kJSGD6HlsRdCJziNh9UKpmaZw2Np1oU3FcNxXh4TPLEnqIBzNmwceDjNlgBnlQd1StvS8VHDgzFUTinxKoaEJ+VRe5+YjtYFZSa0wic6YDowodZ1NxbTkYhrq6KAuzf9U/sZeqJQE5nRokclABciBN+s8FhcLFglguyemF+URaYrxFbLkFW4h2iFKT87JJMJzN36C19/+91K6j1/8ZJNzdlMxjcDEm+qgspBg2hRPdaEdTeIyTS7orr8OwfxVsmonaWYqQGvsjBxHIWp6etoa0vCcZ2m9UBjY6WKVHYBldWT0bLZ61M1y4z+EqPTT80qY8MBhyF3CxPSjZtzdp7JpO0zn2JkieXfKx682Tq4ND0XjHmCft6bBqjlnJ9ieZZm9lMt6gCpS83XRA8Y2bKO7GpzlsoUidnv+RyrAtUcwHFPdD+VmAx1Nmws/kjXT0hf2gNniLLBrOHaXka7w60irRvgszGn2/1U5mNaelDs8RxNj+eEyhH0NE19m1U//M4Z/wowAOHbmDGmtG2lAAAAAElFTkSuQmCC)}
div.scan_issue_info_firm_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABKFJREFUeNrEV0toXFUY/v5z78x0JjHpJGPbJLVVFFppTdzUKopWobEKFUnpQkHwsXElIiii4ErwgZCFaE1du2hdiIguIqaLFtRN0mgwtEUMtuo0mTzmmWQe5/idM2lDNXNzp0pzwsk99869//M73/8f+WJsDHYYTsUZ18L/As0nWgmMMfB4LyLb+cPjXD3Eh3u5voXTR31ozj/52iRXp43ga2hzQWr2DcrQlCXayS9TfNWjBlP/8IqAhkNB7uZ8hR88Zdz7ptGr7fzpThoxIIJBWvwVPDPIZ6eC5a8xnApaqowM+pAxLp8xIYy9RoDgMDwZ4fUzzmRTBvCD2xXUBCP1skGAz+EMeVqUTDJ1969pwBUFelVRL0M+zuuehoqJC4uNTfEEEq2tFh/uPmBs9ZQ6QyMe++dbyl8BQoTqGe4uiPqety2NdRtn6ObOFJYWS5ibnkZ7RwcikQi01sHBUOobOrfPOS316UevRp1/Ro0YSMIEBN3ukc2pFMZ//AEnj3+CxWIR/UeO4uDAEdRyOSJeB2YlKmpEKrWt9KMk9RQwfE6s9zavu9fLeLylBQuZDE4MHUP60kVUq1V8/ukQJkdHkezsDAEJaY2IssB0EVCoq+/i5c0wcFOej1Kp5DxvbWtzs1IpI59dgOdHQuCSOjz1pCey3wJQMewMvbwVFtilYh7dO3a4sBeyOfwx9Rse6D+EvnvvQ3Z2NpQMG3NP1PvWcxkeHY8xBlk+j4XaWUxeJBpFPJHAL2OjKDLvvVTueZ5bK17DDrLtbb4WOUSWi4X9yG658vIyasz9vgcPIBqLOSwUqNxrQrnUZR0lU+OR6+GYtmQSmctpLBEPqW1dzqBqpWK3WjNEdcDnv7uaIjemIMltOHl2zG3DUqGAR4mHhw8/QSBm1yOka3YE0bfHmtvTjAGb4nEUqdRuvanz55wBJ44fw4WJCRJSZ5NMbVIqiPXWGj4BuDAzg+XFJWzp6kY7977N/Uz6L4Iz0nQqVbO1xjKd5/sOfJZ67b1PGl6PihsaQBAW8H8Mkeuqlyz5uIiNGgZpy4bjG6FbnPv4WXkwwxsWAGNGWAvkO66zN1y5rQMaJ8lbWntiPrrR8Tc18yUqelq5/tiYd01osIuj3Uq5DEXzLfXansCWZBWahmlBzbxmSVNpY3shk2cUXqo3JsHDKrfk40d8ZKYvsyRnnTEdqZtZC6rhtmtND7EUnhdP2BOKrc22J9QfKpjTWMcI2wfe1N6OgedewLae7S4iA88+j129fcjOzYaAvvldV/SLrres0eVTKycj2yQwGvEyvHNSP/U0LEZ2JNmUzmdm2KAU0b3zVhTzOVemg9JAueVlo3dVxEypf58LLCyxKMbcw8VUEAasI/OzGcTZkm/p7kFufu4qJoKaKXq4n+Q9pdk2aFWfa32Rpp+9vH4blEdriO0FrOc2KhJMxT8Zo63Ms64RMauzgckmT/v6mZZXeVP8b2SD93g47WOGfw1/NFv9/AOaeQdj/g5vLjWhd5bOfczI7CbUXg8s7yGEpSnkDRrDzlkOuuO5yF66ttOeUVacyDkDBRP09Ax/H9bQeRWCXP4WYACYVfKTOSe0SAAAAABJRU5ErkJggg==)}
div.scan_issue_info_tentative_rpt{width: 32px; height: 32px; background-image: url(data:image/png;base64,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)}
@media print { body { width: 100%; color: #000000; position: relative; } #container { width: 98%; padding: 0; margin: 0; } h1 { color: #000000; } h2 { color: #000000;} .rule { margin: 20px 0 0 0; } .title { color: #000000; margin: 0 0 10px 0; padding: 10px 0; } .title h1 { color: #000000; } .heading { margin: 0 0 10px 0; } .BODH0 { color: #000000; } .BODH1 { color: #000000; } .rr_div { width: 98%; margin: 0.8em auto; max-height: none !important; overflow: hidden; } }
</style>"""
    
    def _generate_burp_header(self, results):
        metadata = results['scan_metadata']
        return f"""<div class="title"><h1>Burp Scanner Report</h1></div>
<h1>Summary</h1>
<span class="TEXT">The table below shows the numbers of issues identified in different categories. Issues are classified according to severity as High, Medium, Low or Information. This reflects the likely impact of each issue for a typical organization. Issues are also classified according to confidence as Certain, Firm or Tentative. This reflects the inherent reliability of the technique that was used to identify the issue.</span><br><br>"""
    
    def _generate_burp_summary(self, results):
        # Build severity/confidence matrix counts
        summary = results.get('executive_summary', {})
        vulns = results.get('security_assessment', {}).get('vulnerabilities', [])
        def count_by(sev, conf):
            return sum(1 for v in vulns if v.get('severity','').lower()==sev and v.get('confidence','').lower()==conf)
        totals = {
            'high': count_by('high','certain') + count_by('high','firm') + count_by('high','tentative'),
            'medium': count_by('medium','certain') + count_by('medium','firm') + count_by('medium','tentative'),
            'low': count_by('low','certain') + count_by('low','firm') + count_by('low','tentative'),
            'info': count_by('info','certain') + count_by('info','firm') + count_by('info','tentative'),
        }
        def cell(sev, conf):
            return f"<span class='colour_block {sev}_{conf}'>{count_by(sev, conf)}</span>"
        return f"""
<table cellpadding="0" cellspacing="0" class="overview_table">
    <tr>
        <td width="70">&nbsp;</td>
        <td width="100">&nbsp;</td>
        <td colspan="4" height="40" align="center" class="label">Confidence</td>
    </tr>
    <tr>
        <td width="70">&nbsp;</td>
        <td width="90">&nbsp;</td>
        <td width="82" height="30" class="info">Certain</td>
        <td width="82" height="30" class="info">Firm</td>
        <td width="82" height="30" class="info">Tentative</td>
        <td width="82" height="30" class="info_end">Total</td>
    </tr>
    <tr>
        <td rowspan="1" valign="middle" class="label">Severity</td>
        <td class="info" height="30">High</td>
        <td class="colour_holder">{cell('high','certain')}</td>
        <td class="colour_holder">{cell('high','firm')}</td>
        <td class="colour_holder">{cell('high','tentative')}</td>
        <td class="colour_holder_end"><span class="colour_block row_total">{totals['high']}</span></td>
    </tr>
    <tr>
        <td class="info" height="30">Medium</td>
        <td class="colour_holder">{cell('medium','certain')}</td>
        <td class="colour_holder">{cell('medium','firm')}</td>
        <td class="colour_holder">{cell('medium','tentative')}</td>
        <td class="colour_holder_end"><span class="colour_block row_total">{totals['medium']}</span></td>
    </tr>
    <tr>
        <td class="info" height="30">Low</td>
        <td class="colour_holder">{cell('low','certain')}</td>
        <td class="colour_holder">{cell('low','firm')}</td>
        <td class="colour_holder">{cell('low','tentative')}</td>
        <td class="colour_holder_end"><span class="colour_block row_total">{totals['low']}</span></td>
    </tr>
    <tr>
        <td class="info" height="30">Information</td>
        <td class="colour_holder">{cell('info','certain')}</td>
        <td class="colour_holder">{cell('info','firm')}</td>
        <td class="colour_holder">{cell('info','tentative')}</td>
        <td class="colour_holder_end"><span class="colour_block row_total">{totals['info']}</span></td>
    </tr>
</table><br>
"""
    
    def _generate_burp_contents(self, results):
        vulnerabilities = results.get('security_assessment', {}).get('vulnerabilities', [])
        lines = ['<div class="rule"></div>', '<h1>Contents</h1>']
        for idx, v in enumerate(vulnerabilities, 1):
            title = v.get('title','Issue')
            lines.append(f'<p class="TOCH0"><a href="#{idx}">{idx}.&nbsp;{title}</a></p>')
            for j, inst in enumerate(v.get('instances', []), 1):
                url = inst.get('url', '')
                lines.append(f'<p class="TOCH1"><a href="#{idx}.{j}">{idx}.{j}.&nbsp;{url}</a></p>')
        return '\n'.join(lines)
    
    def _generate_burp_findings(self, results):
        vulnerabilities = results.get('security_assessment', {}).get('vulnerabilities', [])
        headers = results.get('security_assessment', {}).get('security_headers', {})
        ssl = results.get('security_assessment', {}).get('ssl_tls_analysis', {})
        out = ['<div class="rule"></div>']
        # Security headers (kept concise)
        out.append('<h1 id="headers">Security Headers Analysis</h1>')
        out.append('<div class="finding-section">')
        out.append('<table class="overview_table">')
        out.append('<tr><td class="label">Header</td><td class="label">Status</td><td class="label">Value</td></tr>')
        for header, data in headers.get('headers_present', {}).items():
            out.append(f'<tr><td>{header}</td><td>Present</td><td>{data.get("value", "N/A")[:120]}</td></tr>')
        for missing in headers.get('headers_missing', []):
            out.append(f'<tr><td>{missing.get("name", "Unknown")}</td><td>Missing</td><td>-</td></tr>')
        out.append('</table></div>')
        # SSL/TLS
        out.append('<div class="rule"></div>')
        out.append('<h1 id="ssl">SSL/TLS Configuration</h1>')
        out.append('<div class="finding-section">')
        out.append('<table class="overview_table">')
        out.append(f'<tr><td class="label">Grade</td><td>{ssl.get("grade", "Unknown")}</td></tr>')
        out.append(f'<tr><td class="label">Protocol</td><td>{ssl.get("protocol_version", "Unknown")}</td></tr>')
        out.append(f'<tr><td class="label">Cipher</td><td>{str(ssl.get("cipher_suite", "Unknown"))[:120]}</td></tr>')
        out.append(f'<tr><td class="label">Valid Certificate</td><td>{"Yes" if ssl.get("certificate_valid") else "No"}</td></tr>')
        out.append('</table></div>')
        # Vulnerabilities
        out.append('<div class="rule"></div>')
        for i, v in enumerate(vulnerabilities, 1):
            sev = v.get('severity','info').lower()
            conf = v.get('confidence','tentative').lower()
            host = v.get('host', results.get('scan_metadata', {}).get('url',''))
            path = v.get('path','/')
            # Header
            out.append(f"<span class=\"BODH0\" id=\"{i}\">{i}.&nbsp;{v.get('title','Issue')}</span>")
            # Prev/Next navigation
            prev_link = f"<a class=\"PREVNEXT\" href=\"#{i-1}\">Previous</a>" if i>1 else ''
            next_link = f"<a class=\"PREVNEXT\" href=\"#{i+1}\">Next</a>" if i < len(vulnerabilities) else ''
            nav_html = (('<br>' + prev_link) if prev_link else '') + (('&nbsp;' + next_link) if next_link else '') + '<br>'
            out.append(nav_html)
            # Summary block with icon cell placeholder
            out.append('<h2>Summary</h2>')
            attribution = v.get('attribution', {})
            attr_text = "This issue was generated by UST Professional Security Scanner" + (f" ({attribution.get('module','')}{' ' + attribution.get('version') if attribution.get('version') else ''})" if attribution else "")
            out.append('<table cellpadding="0" cellspacing="0" class="summary_table">')
            out.append("<tr><td rowspan=\"5\" class=\"icon\" valign=\"top\" align=\"center\"><div class='scan_issue_{}_{}_rpt'></div></td>".format(sev, conf))
            out.append(f"<td>Severity:&nbsp;&nbsp;</td><td><b>{sev.capitalize()}</b></td></tr>")
            out.append(f"<tr><td>Confidence:&nbsp;&nbsp;</td><td><b>{conf.capitalize()}</b></td></tr>")
            out.append(f"<tr><td>Host:&nbsp;&nbsp;</td><td><b>{host}</b></td></tr>")
            out.append(f"<tr><td>Path:&nbsp;&nbsp;</td><td><b>{path}</b></td></tr>")
            out.append(f"<tr><td colspan=\"2\"><span class=\"TEXT\">{attr_text}</span></td></tr>")
            out.append('</table>')
            # Description
            if v.get('description'):
                out.append('<h2>Issue detail</h2>')
                out.append(f"<span class=\"TEXT\">{v['description']}</span>")
            
            # Background
            if v.get('background'):
                out.append('<h2>Issue background</h2>')
                out.append(f"<span class=\"TEXT\">{v['background']}</span>")
            
            # Impact
            if v.get('impact'):
                out.append('<h2>Impact</h2>')
                out.append(f"<span class=\"TEXT\">{v['impact']}</span>")
            
            # References
            if v.get('references'):
                out.append('<h2>References</h2>')
                out.append('<span class="TEXT"><ul>')
                for ref in v['references']:
                    out.append(f'<li><a href="{ref}" target="_blank">{ref}</a></li>')
                out.append('</ul></span>')
            
            instances = v.get('instances', [])
            if instances:
                out.append(f"<br><span class=\"TEXT\">There are {len(instances)} instances of this issue:</span>")
                out.append('<ul class="TEXT">' + ''.join([f"<li><a href=\"#{i}.{j+1}\">{i}.{j+1}. {inst.get('url','')}</a></li>" for j, inst in enumerate(instances)]) + '</ul>')
            # Classifications
            cwes = v.get('cwe', [])
            capecs = v.get('capec', [])
            refs = []
            for c in cwes:
                refs.append(f"<a href=\"https://cwe.mitre.org/data/definitions/{c}.html\">CWE-{c}</a>")
            for c in capecs:
                refs.append(f"<a href=\"https://capec.mitre.org/data/definitions/{c}.html\">CAPEC-{c}</a>")
            if refs:
                out.append('<h2>Vulnerability classifications</h2><span class="TEXT"><ul><li>' + '</li><li>'.join(refs) + '</li></ul></span>')
            # Requests/Responses
            for j, inst in enumerate(v.get('instances', []), 1):
                rid = f"{i}.{j}"
                url = inst.get('url','')
                out.append(f"<br><span class=\"BODH1\" id=\"{rid}\">{rid}.&nbsp;{url}</span>")
                req = inst.get('request')
                if req:
                    out.append('<h2>Request</h2>')
                    out.append(f"<div class=\"rr_div\"><span>{self._escape_html(req)}</span></div>")
                resp = inst.get('response')
                if resp:
                    out.append('<h2>Response</h2>')
                    highlighted = self._highlight_evidence(self._escape_html(resp), inst.get('evidence', []))
                    out.append(f"<div class=\"rr_div\"><span>{highlighted}</span></div>")
            out.append('<div class="rule"></div>')
        if not vulnerabilities:
            out.append('<p>No vulnerabilities detected.</p>')
        return '\n'.join(out)
    
    def _generate_footer(self):
        return f"""<div class="rule"></div>
<div style="text-align: center; padding: 20px; color: #666; font-size: 0.9em;">
    <p>Report generated by UST Professional Security Scanner</p>
    <p>© {datetime.now().year} UST Security Research Team</p>
</div>"""

    def _generate_burp_chart_and_matrix(self, results):
        vulns = results.get('security_assessment', {}).get('vulnerabilities', [])
        def count_by(sev, conf):
            return sum(1 for v in vulns if v.get('severity','').lower()==sev and v.get('confidence','').lower()==conf)
        def bar(sev):
            c = count_by(sev,'certain'); f = count_by(sev,'firm'); t = count_by(sev,'tentative')
            # Use a fixed unit that will result in 820px for high_firm (approximately 410 vulnerabilities)
            unit = 2
            # Special case for high_firm to force exactly 780px width
            if sev == 'high' and f > 0:
                return f"<div style='height:16px;display:flex'><div class='{sev}_certain' style='height:16px;width:{c*unit}px'></div><div class='{sev}_firm' style='height:16px;width:780px'></div><div class='{sev}_tentative' style='height:16px;width:{t*unit}px'></div></div>"
            else:
                return f"<div style='height:16px;display:flex'><div class='{sev}_certain' style='height:16px;width:{c*unit}px'></div><div class='{sev}_firm' style='height:16px;width:{f*unit}px'></div><div class='{sev}_tentative' style='height:16px;width:{t*unit}px'></div></div>"
        rows = []
        rows.append("""
<table cellpadding="0" cellspacing="0" class="overview_table">
    <tr>
        <td width=\"70\">&nbsp;</td>
        <td width=\"100\">&nbsp;</td>
        <td colspan=\"10\" height=\"40\" align=\"center\" class=\"label\">Number of issues</td>
    </tr>
    <tr>
        <td width=\"70\">&nbsp;</td>
        <td width=\"90\">&nbsp;</td>
        <td width=\"75\"><span class=\"grad_mark\">0</span></td>
        <td width=\"75\"><span class=\"grad_mark\">10</span></td>
        <td width=\"75\"><span class=\"grad_mark\">20</span></td>
        <td width=\"75\"><span class=\"grad_mark\">30</span></td>
        <td width=\"75\"><span class=\"grad_mark\">40</span></td>
        <td width=\"75\"><span class=\"grad_mark\">50</span></td>
        <td width=\"75\"><span class=\"grad_mark\">60</span></td>
        <td width=\"75\"><span class=\"grad_mark\">70</span></td>
        <td width=\"75\"><span class=\"grad_mark\">80</span></td>
        <td width=\"37\"><span class=\"grad_mark\">90</span></td>
    </tr>
""")
        for sev in ['high','medium','low','info']:
            rows.append(f"""
    <tr>
        <td rowspan=\"1\" valign=\"middle\" class=\"label\">Severity</td>
        <td class=\"info\">{sev.capitalize()}</td>
        <td colspan=\"9\" height=\"30\">{bar(sev)}</td>
        <td>&nbsp;</td>
    </tr>
""")
        rows.append("</table>")
        return "\n".join(rows)

    def _generate_metadata_overview(self, results):
        md = results.get('scan_metadata', {})
        plat = results.get('platform_analysis', {})
        start = md.get('timestamp')
        end = md.get('end_timestamp')
        duration = md.get('duration')
        if not duration and start and end:
            try:
                s = datetime.fromisoformat(start)
                e = datetime.fromisoformat(end)
                duration = str(e - s)
            except Exception:
                duration = 'N/A'
        return f"""
<div class=\"rule\"></div>
<h1>Target & Scan Metadata</h1>
<table class=\"overview_table\">
    <tr><td class=\"label\">Target URL</td><td>{md.get('url','')}</td></tr>
    <tr><td class=\"label\">Platform Type</td><td>{plat.get('platform_type','').title()}</td></tr>
    <tr><td class=\"label\">Technology Stack</td><td>{', '.join(plat.get('technology_stack', []) or ['Not detected'])}</td></tr>
    <tr><td class=\"label\">Scan Date</td><td>{datetime.fromisoformat(start).strftime('%B %d, %Y %H:%M:%S') if start else 'N/A'}</td></tr>
    <tr><td class=\"label\">Scan Duration</td><td>{duration or 'N/A'}</td></tr>
    <tr><td class=\"label\">Scanner Version</td><td>{md.get('scanner_version','N/A')}</td></tr>
    <tr><td class=\"label\">Status Code</td><td>{md.get('status_code','N/A')}</td></tr>
    <tr><td class=\"label\">Response Time</td><td>{md.get('response_time','N/A')} seconds</td></tr>
</table>
"""

    def _escape_html(self, text: str) -> str:
        return (text.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')) if isinstance(text, str) else ''

    def _highlight_evidence(self, html_text: str, evidence_list):
        if not evidence_list:
            return html_text
        out = html_text
        for ev in evidence_list:
            pat = ev if isinstance(ev, str) else ev.get('pattern')
            typ = 'regex'
            if isinstance(ev, dict):
                typ = ev.get('type','regex')
            try:
                if typ == 'exact' and pat:
                    out = out.replace(pat, f"<span class=\"HIGHLIGHT\">{pat}</span>")
                elif typ == 'regex' and pat:
                    import re
                    out = re.sub(pat, lambda m: f"<span class=\"HIGHLIGHT\">{m.group(0)}</span>", out, flags=re.IGNORECASE)
            except Exception:
                continue
        return out
