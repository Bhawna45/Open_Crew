from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    output = ""
    if request.method == "POST":
        target = request.form.get("target")
        
        # Run your existing tool
        result = subprocess.getoutput(f"python main.py {target}")
        output = result

    return render_template("index.html", output=output)

if __name__ == "__main__":
    app.run(debug=True)