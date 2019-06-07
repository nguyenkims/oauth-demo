This project contains a small but complete example of OAuth2 `authorization code grant` flow.

It's composed of a server (that is both authorization and resource server) and a client.

The scenario is a simple OAuth2 flow:
- User goes to a Client website, clicks on "Login with Server"
- User gets redirected to Server website that he can allow the Client to obtain his data
- User gets redirected back to Client website, now authenticated.
  
The goal is to illustrate a complete OAuth2 flow and keep the code as simple as possible. It's composed of
- Server: `server.py` and `templates/server`. Server uses port 5000.
- Client: `client.py` and `templates/client`. Client uses port 7000.

To run the code:

```bash
pip install -r requirements.txt
python client.py # to run the client
```

In another terminal, run the server:

```bash
python server.py
```

After that you can go to `http://localhost:7000` to test the flow. The user credential is

``` 
email: john@wick.com 
password: password
```
