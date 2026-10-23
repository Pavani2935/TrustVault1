"""WSGI entry point for hosts that prefer a module path (gunicorn wsgi:app, mod_wsgi, IIS wfastcgi)."""
from trustvault import create_app

app = create_app()
