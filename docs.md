# DL-JWTSERVER API Documentation
**Temporary Markdown document until proper documentation is setup.**

## Deployment
Clone Git repository containing server application, and run with compatible WSGI server.

## Usage

### Authentication
Key authentication uses a private key associated with the user account, which is then used to create a signature.
When performing signature creation, use the string `SIGNME` as the "message" being signed. Transmitting this "message" string is not nessecary for authentication, please transmit the signature as your `answer` in the request JSON payload. Encode the resulting signature as a plain Base64 string before transmitting.
