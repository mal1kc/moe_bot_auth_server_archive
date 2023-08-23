from . import create_app
import os

if __name__ == "__main__":
    app = app = create_app()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
