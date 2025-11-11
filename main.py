import os
import sys
import argparse
from flask import Flask, render_template, request, redirect, url_for, jsonify
import requests
import shutil
import json
import datetime

# add http if not present
def add_http(url, add_http=True):
    if add_http:
        if url is None:
            return None
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        if not url.endswith("/"):
            url = url + "/"
        return url
    else:
        return url

# information for banner
def banner():
    print("""
Vulnerability Tracker 3.0
author: Muslim Hacker Community
github: 
telegram: https://t.me/MHCChannel
""")

# search cves in database
def search_cve(cve_name):
    path = "cves"
    found = False

    try:
        if not os.path.exists(path):
            print(f"CVE folder : {path} not found.")
            return
            
        all_cves = os.listdir(path)
        for cve_file in all_cves:
            if cve_name.lower() in cve_file.lower():
                print(f"Found CVE: {cve_file}")
                found = True
                break
        if not found:
            print(f"CVE {cve_name} not found in : `{path}` folder.")
    except Exception as e:
        print(f"Error searching CVE: {str(e)}")

# check file path exists
def check_file_path(file_path):
    if file_path is None:
        return False
    return os.path.exists(file_path)

# check git repo valid - IMPROVED VERSION
def check_git_repo(git_repo):
    if not git_repo or not git_repo.strip():
        return False
        
    try:
        git_repo = git_repo.strip()
        
        # Handle SSH URL
        if git_repo.startswith("git@"):
            if "github.com" in git_repo:
                # Convert SSH to HTTPS for validation
                repo_path = git_repo.replace("git@github.com:", "").replace(".git", "")
                owner, repo_name = repo_path.split("/")[:2]
                git_api_url = f"https://api.github.com/repos/{owner}/{repo_name}"
            else:
                return True  # For non-GitHub repos, assume valid
        
        # Handle HTTPS URL
        elif "github.com" in git_repo:
            # Clean the URL
            git_repo = git_repo.replace(".git", "")
            parts = git_repo.split("/")
            
            # Find github.com index
            if "github.com" in parts:
                github_index = parts.index("github.com")
                if len(parts) > github_index + 2:
                    owner = parts[github_index + 1]
                    repo_name = parts[github_index + 2]
                    git_api_url = f"https://api.github.com/repos/{owner}/{repo_name}"
                else:
                    return False
            else:
                return False
        else:
            # For other git repos, assume valid
            return True
        
        # Validate GitHub repository
        response = requests.get(git_api_url, timeout=10)
        return response.status_code == 200
        
    except Exception as e:
        print(f"Git repo validation error: {str(e)}")
        return False

# tools command json file edit - IMPROVED VERSION
class json_file_edit:
    # write json file 
    def write_json(self, file_path, data):
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error writing JSON file: {str(e)}")
            return False
    
    # read json file 
    def read_json(self, file_path):
        if not os.path.exists(file_path):
            return []
        if os.path.getsize(file_path) == 0:
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError as e:
            print(f"JSON decode error in {file_path}: {str(e)}")
            return []
        except Exception as e:
            print(f"Error reading JSON file {file_path}: {str(e)}")
            return []
    
    # update json file
    def update_json(self, file_path, new_data):
        data = self.read_json(file_path)
        if not isinstance(data, list):
            data = []
        data.append(new_data)
        return self.write_json(file_path, data)
    
    # edit json file
    def edit_json(self, file_path, index_no, new_data):
        all_data = self.read_json(file_path)
        
        if 0 <= index_no < len(all_data):
            all_data[index_no] = new_data
            return self.write_json(file_path, all_data)
        else:
            return False
    
    # delete json file entry
    def delete_json_data(self, file_path, index_no):
        all_data = self.read_json(file_path)
        
        if 0 <= index_no < len(all_data):
            all_data.pop(index_no)
            return self.write_json(file_path, all_data)
        else:
            return False

# add cve to database - FIXED FOLDER ISSUE
def add_cve_to_database(command, exp_path=None, git_repo=None):
    data = {'error': None, 'message': None}
    
    print(f"🔍 Starting add_cve_to_database")
    print(f"🔍 exp_path='{exp_path}', git_repo='{git_repo}', command='{command}'")

    json_data_path = 'cves_data.json'
    path = "cves"

    # Create directories if not exists
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"📁 Created directory: {path}")

    # Validate inputs
    if not command or command.strip() == "":
        data['error'] = "Executive command is required"
        return data
        
    if (not exp_path or exp_path.strip() == "") and (not git_repo or git_repo.strip() == ""):
        data['error'] = "Either exploit path or git repository is required"
        return data

    file_name = None
    dest_path = None
    operation_success = False

    try:
        # Handle file path
        if exp_path and exp_path.strip():
            exp_path = exp_path.strip()
            print(f"📄 Processing file path: {exp_path}")
            
            # Check if path exists
            if not os.path.exists(exp_path):
                data['error'] = f"File path does not exist: {exp_path}"
                return data
                
            file_name = os.path.basename(exp_path)
            dest_path = os.path.join(path, file_name)
            print(f"📄 file_name='{file_name}', dest_path='{dest_path}'")

            # Check if destination already exists
            if os.path.exists(dest_path):
                data['error'] = f"CVE {file_name} already exists in the database!"
                return data
            
            print(f"📄 Copying from {exp_path} to {dest_path}")
            
            # Check if it's a file or directory and copy accordingly
            if os.path.isfile(exp_path):
                try:
                    shutil.copy2(exp_path, dest_path)
                    data['message'] = f"CVE {file_name} added successfully from file!"
                    print(f"✅ File copy successful")
                    operation_success = True
                except Exception as copy_error:
                    data['error'] = f"Failed to copy file: {str(copy_error)}"
                    return data
                    
            elif os.path.isdir(exp_path):
                try:
                    # Check if destination directory already exists
                    if os.path.exists(dest_path):
                        data['error'] = f"Destination folder already exists: {dest_path}"
                        return data
                    
                    shutil.copytree(exp_path, dest_path)
                    data['message'] = f"CVE {file_name} added successfully from folder!"
                    print(f"✅ Folder copy successful")
                    operation_success = True
                except Exception as copy_error:
                    data['error'] = f"Failed to copy folder: {str(copy_error)}"
                    return data
            else:
                data['error'] = f"Invalid path: {exp_path}"
                return data

        # Handle git repository
        elif git_repo and git_repo.strip():
            git_repo = git_repo.strip()
            print(f"🐙 Processing git repo: {git_repo}")
            if check_git_repo(git_repo):
                # Extract repo name from URL
                if git_repo.endswith('.git'):
                    repo_name = git_repo.split('/')[-1].replace('.git', '')
                else:
                    repo_name = git_repo.split('/')[-1]
                
                # Remove any query parameters
                repo_name = repo_name.split('?')[0]
                file_name = repo_name
                dest_path = os.path.join(path, repo_name)
                print(f"🐙 repo_name='{repo_name}', dest_path='{dest_path}'")

                if os.path.exists(dest_path):
                    data['error'] = f"CVE {repo_name} already exists in the database!"
                    return data
                
                print(f"🐙 Cloning repository...")
                original_dir = os.getcwd()
                
                try:
                    os.chdir(path)
                    
                    # Clone the repository
                    clone_command = f"git clone {git_repo} {repo_name}"
                    print(f"🐙 Running: {clone_command}")
                    result = os.system(clone_command)
                    
                    os.chdir(original_dir)
                    
                    if result == 0:
                        data['message'] = f"CVE {repo_name} cloned successfully from repository!"
                        operation_success = True
                        print(f"✅ Git clone successful")
                    else:
                        data['error'] = f"Failed to clone repository: {git_repo}"
                        return data
                except Exception as git_error:
                    os.chdir(original_dir)
                    data['error'] = f"Git operation failed: {str(git_error)}"
                    return data
            else:
                data['error'] = f"Invalid git repository: {git_repo}"
                return data

        # Save to JSON if operation was successful
        if operation_success and data['message']:
            print(f"💾 Saving to JSON database...")
            today_date = datetime.date.today().strftime("%d-%m-%Y")
            
            # Determine source type
            source_type = ""
            if exp_path:
                if os.path.isfile(exp_path):
                    source_type = "file"
                elif os.path.isdir(exp_path):
                    source_type = "folder"
            else:
                source_type = "git"
            
            tools_data = {
                "command": command.strip(),
                "date": today_date,
                "file_name": file_name,
                "file_path": dest_path,
                "source_type": source_type,
                "original_source": exp_path if exp_path else git_repo,
                "added_at": datetime.datetime.now().isoformat()
            }
            
            json_editor = json_file_edit()
            existing_data = json_editor.read_json(json_data_path)
            
            if not isinstance(existing_data, list):
                existing_data = []
            
            existing_data.append(tools_data)
            success = json_editor.write_json(json_data_path, existing_data)
            
            if success:
                data['message'] += " and saved to database!"
                print(f"✅ JSON save successful")
            else:
                data['error'] = "Failed to save to database"
                operation_success = False

    except Exception as e:
        print(f"❌ Exception occurred: {str(e)}")
        data['error'] = f"Operation failed: {str(e)}"
        
        # Clean up on error
        if dest_path and os.path.exists(dest_path):
            try:
                if os.path.isfile(dest_path):
                    os.remove(dest_path)
                elif os.path.isdir(dest_path):
                    shutil.rmtree(dest_path)
                print(f"🧹 Cleaned up {dest_path}")
            except Exception as cleanup_error:
                print(f"❌ Cleanup failed: {cleanup_error}")

    print(f"🎯 Final response - error: {data['error']}, message: {data['message']}")
    return data

# Get all CVEs with pagination
def get_all_cves(page=1, per_page=10, search_term=""):
    json_data_path = 'cves_data.json'
    json_editor = json_file_edit()
    all_cves = json_editor.read_json(json_data_path)
    
    # Filter by search term if provided
    if search_term:
        all_cves = [cve for cve in all_cves if search_term.lower() in cve.get('file_name', '').lower()]
    
    # Calculate pagination
    total = len(all_cves)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_cves = all_cves[start:end]
    
    return {
        "cves": paginated_cves,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 1
    }

# Delete CVE from database
def delete_cve_from_database(index):
    json_data_path = 'cves_data.json'
    json_editor = json_file_edit()
    all_cves = json_editor.read_json(json_data_path)
    
    if 0 <= index < len(all_cves):
        cve_data = all_cves[index]
        file_path = cve_data.get('file_path')
        
        # Delete physical file/folder
        try:
            if file_path and os.path.exists(file_path):
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                print(f"🧹 Deleted {file_path}")
        except Exception as e:
            return {"error": f"Failed to delete file: {str(e)}"}
        
        # Delete from JSON
        if json_editor.delete_json_data(json_data_path, index):
            return {"message": "CVE deleted successfully"}
        else:
            return {"error": "Failed to delete from database"}
    else:
        return {"error": "Invalid CVE index"}

# Update CVE in database
def update_cve_in_database(index, new_command):
    json_data_path = 'cves_data.json'
    json_editor = json_file_edit()
    all_cves = json_editor.read_json(json_data_path)
    
    if 0 <= index < len(all_cves):
        cve_data = all_cves[index]
        cve_data['command'] = new_command
        cve_data['updated_at'] = datetime.datetime.now().isoformat()
        
        if json_editor.edit_json(json_data_path, index, cve_data):
            return {"message": "CVE updated successfully"}
        else:
            return {"error": "Failed to update CVE"}
    else:
        return {"error": "Invalid CVE index"}

# run all tools function - FIXED VERSION
def run_all(url, cmd="ls", threads=10):
    original_path = os.getcwd()
    path = "cves/"
    
    # Check if cves directory exists
    if not os.path.exists(path):
        print(f"❌ Error: CVE directory '{path}' not found!")
        return
    
    json_editor = json_file_edit()
    tools_cmd = "cves_data.json"
    
    try:
        file_data = json_editor.read_json(tools_cmd)
        if not file_data:
            print("❌ No CVE data found in database!")
            return
            
        print(f"🎯 Starting scan on: {url}")
        print(f"🔧 Using command template: {cmd}")
        print(f"🧵 Threads: {threads}")
        print("-" * 50)
        
        for tool in file_data:
            file_name = tool.get('file_name', '')
            file_path = os.path.join(path, file_name)
            command = tool.get('command', '')
            
            if not file_name or not command:
                print(f"⚠️ Skipping invalid tool entry: {tool}")
                continue

            # Replace placeholders in command
            command = command.replace("/TARGET/", f"{url}").replace("/CMD/", f"{cmd}").replace("/AUTO/", f"{threads}")

            print(f"🔧 Running => {file_name}")
            print(f"   Command: {command}")
            
            # Change to the specific tool directory if it exists
            if os.path.exists(file_path):
                if os.path.isdir(file_path):
                    # It's a directory - run command inside the directory
                    os.chdir(file_path)
                    return_code = os.system(command)
                    os.chdir(original_path)
                    if return_code == 0:
                        print(f"✅ {file_name} completed successfully")
                    else:
                        print(f"❌ {file_name} exited with error code: {return_code}")
                else:
                    # It's a file - run from cves directory
                    os.chdir(path)
                    return_code = os.system(f"{command} {file_name}")
                    os.chdir(original_path)
                    if return_code == 0:
                        print(f"✅ {file_name} completed successfully")
                    else:
                        print(f"❌ {file_name} exited with error code: {return_code}")
            else:
                print(f"❌ File/Directory not found: {file_path}")
            
            print("-" * 30)
                
    except Exception as e:
        print(f"❌ Error running tools: {str(e)}")
        os.chdir(original_path)
    
    os.chdir(original_path)
    print("🎊 Scan completed!")

# all information - FIXED VERSION
def information():
    banner()
    print("Vulnerability Tracker 3.0")

    # count total tools 
    json_data_path = 'cves_data.json'
    json_editor = json_file_edit()
    json_data = json_editor.read_json(json_data_path)
    total_tools = len(json_data) if isinstance(json_data, list) else 0
    
    print(f"Total CVEs in database: {total_tools}")
    
    # Check if cves directory exists
    cves_path = "cves"
    if os.path.exists(cves_path):
        actual_files = len([f for f in os.listdir(cves_path) if not f.startswith('.')])
        print(f"Actual files in cves directory: {actual_files}")
    
    print("Last added CVE in database:")
    if total_tools > 0:
        last_cve = json_data[-1]
        print(f"  - Name: {last_cve.get('file_name', 'N/A')}")
        print(f"  - Path: {last_cve.get('file_path', 'N/A')}")
        print(f"  - Command: {last_cve.get('command', 'N/A')}")
        print(f"  - Date Added: {last_cve.get('date', 'N/A')}")
        print(f"  - Source Type: {last_cve.get('source_type', 'N/A')}")
    else:
        print("  - No CVEs in database")
    
    print("Default commands : \n    /TARGET/ - Target URL\n    /CMD/ - Command to execute\n    /AUTO/ - Number of threads\n")

# flask server functions 
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("add.html")

@app.route("/", methods=['POST'])
def add_cve():
    try:
        data = request.get_json()
        print(f"🌐 WEB: Received POST data - {data}")
        
        exp_path = data.get('exp_path', '').strip()
        git_repo = data.get('git_repo', '').strip()
        exec_cmd = data.get('exec_cmd', '').strip()
        
        # Validate required fields
        if not exec_cmd:
            return jsonify({"error": "Executive command is required"}), 400
            
        # Call the function to add CVE to database
        result = add_cve_to_database(exec_cmd, exp_path, git_repo)
        print(f"🌐 WEB: Function result - {result}")
        
        if result.get('message'):
            return jsonify({"message": result['message']})
        else:
            return jsonify({"error": result.get('error', 'Unknown error occurred')}), 400
            
    except Exception as e:
        print(f"🌐 WEB: Exception - {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# API routes for CVE management
@app.route("/api/cves", methods=['GET'])
def api_get_cves():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)
    result = get_all_cves(page=page, per_page=per_page, search_term=search)
    return jsonify(result)

@app.route("/api/cves/<int:index>", methods=['DELETE'])
def api_delete_cve(index):
    result = delete_cve_from_database(index)
    if result.get('message'):
        return jsonify(result)
    else:
        return jsonify(result), 400

@app.route("/api/cves/<int:index>", methods=['PUT'])
def api_update_cve(index):
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
        
    new_command = data.get('command', '').strip()
    
    if not new_command:
        return jsonify({"error": "Command is required"}), 400
        
    result = update_cve_in_database(index, new_command)
    if result.get('message'):
        return jsonify(result)
    else:
        return jsonify(result), 400

# main function - FIXED VERSION
def main():
    parser = argparse.ArgumentParser(description="Vulnerability Tracker 3.0")
    parser.add_argument("-u", "--url", help="Target URL", required=False, type=str)
    parser.add_argument("-v", "--version", action="version", version="Vulnerability Tracker 3.0")
    parser.add_argument("-g", "--gui", help="Launch GUI (web interface)", action="store_true")
    parser.add_argument("-t", "--threads", help="Number of threads (default: 10)", type=int, default=10)
    parser.add_argument("-c", "--cmd", help="Command to execute (default: ls)", type=str, default="ls")
    parser.add_argument('-i','--info', help='Show information', action='store_true')
    parser.add_argument("-s", "--search", help="Search CVE in database", type=str)
    parser.add_argument("-a","--add", help="Add http/https if not present", action="store_true")
    parser.add_argument("-d","--debug", help="Enable debug mode", action="store_true")
    args = parser.parse_args()

    banner()

    if args.gui:
        print("🚀 Launching web interface...")
        app.run(debug=args.debug, host='0.0.0.0', port=5000)
    elif args.search:
        search_cve(args.search)
    elif args.info:
        information()
    elif args.url:
        target_url = add_http(args.url, args.add)
        print(f"🎯 Target URL: {target_url}")
        print(f"🔧 Command: {args.cmd}")
        print(f"🧵 Threads: {args.threads}")
        run_all(target_url, cmd=args.cmd, threads=args.threads)
    else:
        print("No arguments provided. Use -h for help.")
        print("Available options:")
        print("  -g, --gui     Launch web interface")
        print("  -u, --url     Target URL with -c and -t options")
        print("  -s, --search  Search CVE in database")
        print("  -i, --info    Show information")
        print("  -h, --help    Show help message")

if __name__ == "__main__":
    main()