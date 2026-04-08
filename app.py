import time
from flask import Flask, render_template, request
from google.cloud import monitoring_v3

app = Flask(__name__)

# Constants for log sizes (KB) based on GCP entry metadata overhead
# Data Access logs are larger due to identity/resource metadata.
LOG_CONFIG = {
    "lb": {"metric": "loadbalancing.googleapis.com/https/request_count", "size": 1.0, "label": "Load Balancer Logs"},
    "dns": {"metric": "dns.googleapis.com/query_count", "size": 0.5, "label": "Cloud DNS Logs (for ETD)"},
    "waf": {"metric": "library.googleapis.com/waf/requests", "size": 1.8, "label": "Cloud Armor/WAF Logs"},
    "gcs_audit": {"metric": "storage.googleapis.com/api/request_count", "size": 1.5, "label": "GCS Data Access (Audit)"},
    "bq_audit": {"metric": "bigquery.googleapis.com/query/count", "size": 1.2, "label": "BigQuery Data Access (Audit)"},
    "iap": {"metric": "iap.googleapis.com/request_count", "size": 0.7, "label": "IAP Access Logs"}
}

COST_PER_GB = 0.50

def fetch_monthly_metric_count(project_id, metric_type):
    client = monitoring_v3.MetricServiceClient()
    project_name = f"projects/{project_id}"
    
    # Analyze 7 days to get a baseline and extrapolate for 30 days
    now = time.time()
    interval = monitoring_v3.TimeInterval({
        "end_time": {"seconds": int(now)},
        "start_time": {"seconds": int(now - 604800)}, 
    })

    try:
        results = client.list_time_series(
            name=project_name,
            filter=f'metric.type = "{metric_type}"',
            interval=interval,
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        )
        total = 0
        for series in results:
            for point in series.points:
                total += point.value.int64_value
        
        # Extrapolate to 30 days
        return (total / 7) * 30
    except Exception as e:
        print(f"Error fetching {metric_type}: {e}")
        return 0

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        project_id = request.form.get('project_id')
        selected_features = request.form.getlist('features')
        
        estimates = []
        grand_total_gb = 0
        
        for key in selected_features:
            conf = LOG_CONFIG[key]
            monthly_count = fetch_monthly_metric_count(project_id, conf['metric'])
            
            # Math: (Requests * KB size) / 1024^2 = GiB
            size_gb = (monthly_count * conf['size']) / 1048576
            cost = size_gb * COST_PER_GB
            
            estimates.append({
                "name": conf['label'],
                "volume": round(size_gb, 3),
                "cost": round(cost, 2)
            })
            grand_total_gb += size_gb

        results = {
            "project_id": project_id,
            "items": estimates,
            "total_cost": round(grand_total_gb * COST_PER_GB, 2)
        }

    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
