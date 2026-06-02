from flask import Flask, render_template_string
import csv

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>Shadow IT Dashboard</title>
  <style>
    body { font-family: Arial; padding: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background: #f2f2f2; }
    .HIGH { background-color: #ffcccc; }
    .MEDIUM { background-color: #fff0b3; }
    .LOW { background-color: #ccffcc; }
  </style>
</head>
<body>
<h2>Shadow IT Detection Dashboard</h2>
<table>
<tr>
  <th>Timestamp</th>
  <th>Domain</th>
  <th>User IP</th>
  <th>Server IP</th>
  <th>Risk</th>
</tr>
{% for row in rows %}
<tr class="{{ row['risk'] }}">
  <td>{{ row['timestamp'] }}</td>
  <td>{{ row['domain'] }}</td>
  <td>{{ row['user_ip'] }}</td>
  <td>{{ row['server_ip'] }}</td>
  <td>{{ row['risk'] }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

@app.route("/")
def dashboard():
    rows = []
    try:
        with open("reports/shadowit_report.csv") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except:
        pass
    return render_template_string(HTML_TEMPLATE, rows=rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
