from flask import Flask, render_template, request
from config import Config
from detector import analyze_url


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/scanner", methods=["GET", "POST"])
    def scanner():
        result = None
        error = None
        if request.method == "POST":
            url = request.form.get("url", "")
            try:
                analysis = analyze_url(url)
                result = {"url": analysis.pop("normalized_url"), **analysis}
            except ValueError as exc:
                error = str(exc)
        return render_template("scanner.html", result=result, error=error)

    @app.route("/case-study")
    def case_study():
        return render_template("case_study.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])
