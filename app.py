from flask import Flask, render_template, request

app = Flask(__name__)

def simple_rule_based_model(url: str):
    url_lower = url.lower()
    score = 0
    suspicious_tokens = ["login", "verify", "update", "free", "gift", "secure", "confirm"]
    for tok in suspicious_tokens:
        if tok in url_lower:
            score += 1
    if len(url) > 80:
        score += 1
    if url.count("@") > 0 or url.count("-") > 3:
        score += 1
    if url_lower.startswith("http://"):
        score += 1

    if score >= 2:
        pred = "Phishing"
        reason = "URL contains multiple suspicious patterns such as keywords, length or characters."
    else:
        pred = "Legitimate"
        reason = "No strong phishing indicators detected in basic lexical checks."
    return pred, reason

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    reason = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        prediction, reason = simple_rule_based_model(url)
    return render_template("index.html", prediction=prediction, reason=reason)

if __name__ == "__main__":
    app.run(debug=True)
