from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route('/hello')
def hello():
    name = request.args.get('name')
    # xss via unsanitized input
    template = "Hello " + name
    return render_template_string(template)