from http.server import SimpleHTTPRequestHandler, HTTPServer
import requests

class CustomRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == '/1':
                response = requests.get("http://http_b:8000")
            elif self.path == '/2':
                response = requests.get("http://http_c:8000")
            else:
                raise Exception
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(("This is from HTTP-A service. " + response.text + "\n").encode("utf-8"))
        except Exception as e:
            print(e, flush=True)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Error fetching data in HTTP-A service")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), CustomRequestHandler)
    print("Server running on port 8000...")
    server.serve_forever()
