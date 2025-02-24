from flask import Flask, request, jsonify
import subprocess
import xml.etree.ElementTree as ET
import time

app = Flask(__name__)
#TODO: Well the script is so insecure its almost like I want to build a backdoor all over the place ;)
#TODO: Fix Command Injection vulns
#? Create target
@app.route('/create_target', methods=['POST'])
def create_target():
    data = request.get_json()
    command = data['command']
    
    #? Create target
    targetID = subprocess.getoutput(command)
    
    if 'Error' in targetID:
        return jsonify({'message': 'Failed to create target'})
    else:
        root = ET.fromstring(targetID)
        targetID = root.attrib['id']
        print(f"targetid: {targetID}")
        time.sleep(1)
        return jsonify({'message': targetID})


#? Create task
@app.route('/create_task', methods=['POST'])
def create_task():
    data = request.get_json()
    command = data['command']
    
    #? Create task
    taskID = subprocess.getoutput(command)
    
    if 'Error' in taskID:
        return jsonify({'message': 'Failed to create task'})
    else:
        root = ET.fromstring(taskID)
        taskID = root.attrib['id']
        print(f"Taskid: {taskID}")
        time.sleep(1)
        return jsonify({'message': taskID})


#? run_task
@app.route('/run_task', methods=['POST'])
def run_task():
    data = request.get_json()
    command = data['command']
    
    #? Run task
    reportID = subprocess.getoutput(command)
    
    if 'Error' in reportID:
        return jsonify({'message': 'Failed to run task'})
    else:
        
        reportID = reportID.split(">")[2].split("<")[0]
        print(f"reportid: {reportID}")
        time.sleep(1)
        return jsonify({'message': reportID})

#? check_if_finished
@app.route('/check_if_finished', methods=['POST'])
def check_if_finished():
    data = request.get_json()
    command = data['command']
    print(command)
    
    #? Check if finished
    status = subprocess.getoutput(command)
    print(f"Status: {status}")
    return jsonify({'message': status})

#? get report
@app.route('/get_report', methods=['POST'])
def get_report():
    data = request.get_json()
    command = data['command']

    report_data = subprocess.getoutput(command)
    print(f"report data: {report_data}")
    
    return jsonify({'message': report_data})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


