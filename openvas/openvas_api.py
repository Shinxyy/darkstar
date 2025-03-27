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
    print(f"Executing command: {command}")
    taskID = subprocess.getoutput(command)
    print(f"Raw response from create_task command: {taskID}")
    
    if 'Error' in taskID:
        return jsonify({'message': 'Failed to create task'})
    else:
        try:
            root = ET.fromstring(taskID)
            # Fix: Find the task ID in the correct location in the XML
            # The ID might be in the 'create_task_response' element or a child element
            if 'id' in root.attrib:
                taskID = root.attrib['id']
                print(f"Found task ID in root attributes: {taskID}")
            else:
                # Debug XML structure
                print(f"XML structure: {ET.tostring(root).decode('utf-8')}")
                print(f"Root tag: {root.tag}")
                print(f"Root attributes: {root.attrib}")
                
                # Try to find the create_task_response element or task element
                create_task_resp = root.find('.//create_task_response') or root.find('.//task')
                if create_task_resp is not None:
                    print(f"Found element: {create_task_resp.tag} with attributes: {create_task_resp.attrib}")
                    if 'id' in create_task_resp.attrib:
                        taskID = create_task_resp.attrib['id']
                        print(f"Found task ID in {create_task_resp.tag}: {taskID}")
                    else:
                        # Look for id in child elements
                        for child in create_task_resp:
                            print(f"Child element: {child.tag} with text: {child.text}")
                            if child.tag == 'id':
                                taskID = child.text
                                print(f"Found task ID in child element: {taskID}")
                                break
                else:
                    # If we can't find the id in the expected places, extract it from raw XML
                    # This is a fallback method that assumes the id is somewhere in the response
                    print("Could not find create_task_response or task element, trying regex")
                    import re
                    id_match = re.search(r'id="([^"]+)"', taskID)
                    if id_match:
                        taskID = id_match.group(1)
                        print(f"Found task ID with regex: {taskID}")
                    else:
                        print("Regex extraction failed. Checking for any UUID-like pattern")
                        uuid_match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', taskID)
                        if uuid_match:
                            taskID = uuid_match.group(1)
                            print(f"Found potential task ID with UUID pattern: {taskID}")
                        else:
                            print("All extraction methods failed")
                            return jsonify({'message': 'Failed to extract task ID from response'})
            
            print(f"Final taskid: {taskID}")
            time.sleep(1)
            return jsonify({'message': taskID})
        except Exception as e:
            print(f"Error parsing task ID: {e}")
            print(f"Raw response: {taskID}")
            return jsonify({'message': 'Failed to parse task ID from response: ' + str(e)})


#? run_task
@app.route('/run_task', methods=['POST'])
def run_task():
    data = request.get_json()
    command = data['command']
    
    #? Run task
    print(f"Executing run_task command: {command}")
    reportID = subprocess.getoutput(command)
    print(f"Raw response from run_task: {reportID}")
    
    if 'Error' in reportID or 'Failed' in reportID or 'status="404"' in reportID:
        print(f"Error detected in response: {reportID}")
        return jsonify({'message': f'Failed to run task: {reportID}'})
    else:
        try:
            # Try to parse the response as XML first
            try:
                print("Attempting to parse XML response")
                root = ET.fromstring(reportID)
                print(f"Root tag: {root.tag}, attributes: {root.attrib}")
                
                # Check for error status
                if 'status' in root.attrib and root.attrib['status'] in ['404', '400', '500']:
                    print(f"Error status in response: {root.attrib}")
                    if 'status_text' in root.attrib:
                        return jsonify({'message': f'Error: {root.attrib["status_text"]}'})
                    return jsonify({'message': f'Error status: {root.attrib["status"]}'})
                
                # Check for report_id attribute in start_task_response
                start_task_resp = root.find('.//start_task_response')
                if start_task_resp is not None:
                    print(f"Found start_task_response with attributes: {start_task_resp.attrib}")
                    if 'report_id' in start_task_resp.attrib:
                        reportID = start_task_resp.attrib['report_id']
                        print(f"Found report_id in attributes: {reportID}")
                    else:
                        print("No report_id attribute found")
                else:
                    print("No start_task_response element found")
                
                # Try to find the report ID in the XML content
                report_id_elem = root.find('.//report_id')
                if report_id_elem is not None:
                    reportID = report_id_elem.text
                    print(f"Found report_id element with text: {reportID}")
                else:
                    print("No report_id element found")
                    
                # Print full XML for debugging
                print(f"Full XML structure: {ET.tostring(root).decode('utf-8')}")
                
                # Fallback: extract using regex
                import re
                print("Trying regex extraction")
                report_id_match = re.search(r'<report_id>(.*?)</report_id>', reportID)
                if report_id_match:
                    reportID = report_id_match.group(1)
                    print(f"Found report_id with regex: {reportID}")
                else:
                    print("Regex extraction failed")
                    
                    # Last resort: try the original split method with better error handling
                    print("Trying split method")
                    parts = reportID.split(">")
                    for i, part in enumerate(parts):
                        print(f"Part {i}: {part}")
                    
                    if len(parts) > 2:
                        try:
                            reportID = parts[2].split("<")[0]
                            print(f"Split method extracted: {reportID}")
                        except IndexError:
                            print("Split method failed due to index error")
                    else:
                        print("Not enough parts for split method")
                        
                        # Try to find any UUID pattern
                        uuid_match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', reportID)
                        if uuid_match:
                            reportID = uuid_match.group(1)
                            print(f"Found UUID pattern: {reportID}")
                        else:
                            print(f"Unable to extract report ID. Raw response: {reportID}")
                            return jsonify({'message': 'Failed to extract report ID'})
            except ET.ParseError as e:
                print(f"XML parsing failed: {e}")
                # If XML parsing fails, try regex extraction
                import re
                print("Trying regex after XML parse failure")
                report_id_match = re.search(r'<report_id>(.*?)</report_id>', reportID)
                if report_id_match:
                    reportID = report_id_match.group(1)
                    print(f"Found report_id with regex: {reportID}")
                else:
                    print("Regex extraction failed")
                    # Try to find any UUID pattern
                    uuid_match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', reportID)
                    if uuid_match:
                        reportID = uuid_match.group(1)
                        print(f"Found UUID pattern: {reportID}")
                    else:
                        # Try the original method with better error checking
                        print("Trying original split method")
                        parts = reportID.split(">")
                        if len(parts) > 2 and "<" in parts[2]:
                            reportID = parts[2].split("<")[0]
                            print(f"Split method extracted: {reportID}")
                        else:
                            print(f"Unable to extract report ID. Raw response: {reportID}")
                            return jsonify({'message': 'Failed to extract report ID'})
            
            print(f"Final reportid: {reportID}")
            time.sleep(1)
            return jsonify({'message': reportID})
        except Exception as e:
            print(f"Error extracting report ID: {e}")
            print(f"Raw response: {reportID}")
            return jsonify({'message': 'Error extracting report ID: ' + str(e)})

#? check_if_finished
@app.route('/check_if_finished', methods=['POST'])
def check_if_finished():
    data = request.get_json()
    command = data['command']
    print(f"Executing check_if_finished command: {command}")
    
    #? Check if finished
    status = subprocess.getoutput(command)
    print(f"Raw response from check_if_finished: {status}")
    
    # Check for common error patterns
    if 'Failed to find report format' in status or 'status="404"' in status:
        print("Error detected in check_if_finished response")
        # Try to extract the error message
        try:
            root = ET.fromstring(status)
            if 'status_text' in root.attrib:
                error_msg = root.attrib['status_text']
                print(f"Error message from XML: {error_msg}")
        except:
            error_msg = "Unknown error in check_if_finished"
        
        return jsonify({'message': f"<error>{error_msg}</error>"})
    
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


