
import os
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/read')
def read_file():
    filename = request.args.get('file')
    
    # VULNERABLE: Path Traversal
    # User can pass "../../../etc/passwd"
    with open(filename, 'r') as f:
        return f.read()

@app.route('/go')
def jump():
    target = request.args.get('url')
    
    # VULNERABLE: Open Redirect
    return redirect(target)

if __name__ == '__main__':
    app.run()
