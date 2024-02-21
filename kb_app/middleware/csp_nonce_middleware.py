import base64
import os
from django.utils.deprecation import MiddlewareMixin

class CSPNonceMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Generate a nonce
        nonce = base64.b64encode(os.urandom(16)).decode()
        request.csp_nonce = nonce

    def process_response(self, request, response):
        # Add the nonce to the CSP header
        if hasattr(request, 'csp_nonce'):
            csp = ("script-src 'self' 'nonce-{}' "
                "https://cdn.datatables.net "
                "https://cdn.jsdelivr.net "
                "https://cdn.quilljs.com "
                "https://code.jquery.com; "
                "frame-ancestors 'self'; "  # Restrict framing of your site to same origin
                "form-action 'self';"  # Restrict form submission to same origin
                ).format(request.csp_nonce)
            response['Content-Security-Policy'] = csp
        return response