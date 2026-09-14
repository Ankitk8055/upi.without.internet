"""
run.py
-------
Entry point. Equivalent of `mvnw spring-boot:run` / UpiMeshApplication.java.

Usage:
    python run.py
Then open http://localhost:8080
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
