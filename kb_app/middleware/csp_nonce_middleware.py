import base64
import os
from django.utils.deprecation import MiddlewareMixin

class CSPNonceMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Generate a nonce
        nonce = base64.b64encode(os.urandom(16)).decode()
        request.csp_nonce = nonce

    def process_response(self, request, response):
        # Add the nonce and other CSP directives
        if hasattr(request, 'csp_nonce'):
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'nonce-{}' ; "
                "style-src 'self' 'sha256-r06yVUBqP+7ZbDWovXc9AqepL8NwsS69BQIUpScMDvU=' 'sha256-0EZqoz+oBhx7gF4nvY2bSqoGyy4zLjNF+SDQXGp/ZrY=' 'sha256-RvAvREUHojDuwHylTVWZp9DhleqLs6ml8G7LpjCF+EY=' 'sha256-aqNNdDLnnrDOnTNdkJpYlAxKVJtLt9CtFLklmInuUAE='; "
                "img-src 'self' data: *; "
                "connect-src 'self'; "
                "frame-src 'self'; "
                "font-src 'self'; "
                "media-src 'self'; "
                "object-src 'none'; "
                "manifest-src 'self'; "
                "frame-ancestors 'self'; "  # Restrict framing of your site to same origin
                "form-action 'self';"  # Restrict form submission to same origin
            ).format(request.csp_nonce)
            response['Content-Security-Policy'] = csp
        return response