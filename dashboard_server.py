import os
import json
import subprocess
import time
import threading
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='output')
CORS(app)

# Global state
pipeline_process = None
pipeline_start_time = None
pipeline_lock = threading.Lock()

@app.route('/')
def index():
    return send_from_directory('output', 'dashboard.html')

@app.route('/output/<path:filename>')
def serve_output(filename):
    return send_from_directory('output', filename)

@app.route('/status')
def status():
    with pipeline_lock:
        is_running = pipeline_process is not None and pipeline_process.poll() is None
        return jsonify({
            'running': is_running,
            'last_run': pipeline_start_time
        })

@app.route('/results')
def results():
    report_path = os.path.join('output', 'report.json')
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'No results found'}), 404

@app.route('/run', methods=['POST'])
def run_pipeline():
    global pipeline_process, pipeline_start_time
    
    data = request.json
    if not data or not data.get('conn') or not data.get('dns'):
        return jsonify({'error': 'conn and dns logs are required'}), 400

    with pipeline_lock:
        if pipeline_process is not None and pipeline_process.poll() is None:
            return jsonify({'error': 'Pipeline is already running'}), 409

        cmd = ['python', 'main.py']
        cmd.extend(['--conn', data['conn']])
        cmd.extend(['--dns', data['dns']])
        if data.get('ssl'):
            cmd.extend(['--ssl', data['ssl']])
        if data.get('min_score'):
            cmd.extend(['--min-score', str(data['min_score'])])
        
        if data.get('threat_intel'):
            # Note: assuming main.py has an --intel flag based on previous modules context
            cmd.extend(['--intel', data['threat_intel']])
            
        output_format = data.get('output_format', 'json').lower()
        cmd.extend(['--output', output_format])
        cmd.append('--report')

        pipeline_start_time = time.time()
        pipeline_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

    def generate():
        try:
            for line in iter(pipeline_process.stdout.readline, ''):
                if line:
                    yield f"data: {line.strip()}\n\n"
            pipeline_process.stdout.close()
            pipeline_process.wait()
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: ERROR: {str(e)}\n\n"
            
    return Response(generate(), mimetype='text/event-stream')

@app.route('/stop', methods=['POST'])
def stop_pipeline():
    global pipeline_process
    with pipeline_lock:
        if pipeline_process is not None and pipeline_process.poll() is None:
            pipeline_process.terminate()
            return jsonify({'status': 'stopped'})
        return jsonify({'status': 'not running'})

if __name__ == '__main__':
    print("Zeek C2 Hunter dashboard running at http://localhost:5000")
    print("Open that URL in your browser.")
    app.run(host='127.0.0.1', port=5000, threaded=True)
